const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config();
const cron = require('node-cron');
const rateLimit = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1); // Render sta dietro un proxy: serve per leggere l'IP reale del client
app.use(cors());
app.use(express.json({ limit: '10kb' }));

// Rate limiting per IP: generale su tutte le API + più stretto sulle scritture
app.use('/api', rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false }));
const limiteScritture = rateLimit({
    windowMs: 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false,
    skip: (req) => req.method === 'GET',
    message: { error: "Troppe richieste, riprova tra un minuto" },
});
app.use('/api/prenotazioni', limiteScritture);
app.use('/api/auth', limiteScritture);

// ==========================================
// CONFIGURAZIONE DATABASE
// ==========================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

app.listen(process.env.PORT, () => {
    console.log(`Server avviato sulla porta ${process.env.PORT}`);
});

// Assicura che le colonne esistano (idempotente)
pool.query("ALTER TABLE profili ADD COLUMN IF NOT EXISTS telefono TEXT").catch(err => {
    console.log('DB init profili.telefono:', err.message);
});
pool.query("ALTER TABLE prenotazioni ADD COLUMN IF NOT EXISTS cliente_telefono TEXT").catch(err => {
    console.log('DB init prenotazioni.cliente_telefono:', err.message);
});

// Pulizia duplicati + vincolo unicità slot (previene race condition nelle prenotazioni)
(async () => {
    try {
        // Rimuove eventuali doppioni mantenendo la prenotazione con id più alto (più recente)
        await pool.query(`
            DELETE FROM prenotazioni
            WHERE stato = 'attivo' AND id NOT IN (
                SELECT MAX(id) FROM prenotazioni
                WHERE stato = 'attivo'
                GROUP BY barbiere_id, data, ora
            )
        `);
        // Crea unique partial index: impedisce che lo stesso slot venga prenotato due volte
        await pool.query(`
            CREATE UNIQUE INDEX IF NOT EXISTS uniq_slot_attivo
            ON prenotazioni (barbiere_id, data, ora)
            WHERE stato = 'attivo'
        `);
        console.log('DB: vincolo unicità slot prenotazioni OK');
    } catch (e) {
        console.log('DB init unicità slot:', e.message);
    }
})();

// ==========================================
// MIDDLEWARE AUTH
// ==========================================
// Cache token → utente (evita di chiamare Supabase ad ogni richiesta e bypassa il rate limit)
const tokenCache = new Map(); // token → { utente, scadenza }
setInterval(() => {
    const adesso = Date.now();
    for (const [k, v] of tokenCache) {
        if (v.scadenza < adesso) tokenCache.delete(k);
    }
}, 60 * 1000); // pulizia ogni minuto

const verificaToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "Accesso non autorizzato" });
    }
    try {
        const token = authHeader.split(' ')[1];

        // Controlla cache prima di chiamare Supabase
        req.token = token;
        const cached = tokenCache.get(token);
        if (cached && cached.scadenza > Date.now()) {
            req.utente = cached.utente;
            return next();
        }

        const risposta = await fetch(`${process.env.SUPABASE_URL}/auth/v1/user`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'apikey': process.env.SUPABASE_ANON_KEY,
            }
        });

        if (!risposta.ok) {
            return res.status(401).json({ error: "Token non valido o scaduto" });
        }

        const userData = await risposta.json();
        const uuid = userData.id;

        const result = await pool.query(
            `SELECT p.id, p.ruolo, p.nome, p.cognome, p.telefono, b.id AS barbiere_id
             FROM profili p
             LEFT JOIN barbieri b ON b.profilo_id = p.id
             WHERE p.id = $1`,
            [uuid]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: "Utente non trovato" });
        }

        const u = result.rows[0];

        const telefonoMeta = userData.user_metadata?.telefono || null;
        const telefono = u.telefono || telefonoMeta;
        if (!u.telefono && telefono) {
            pool.query('UPDATE profili SET telefono = $1 WHERE id = $2', [telefono, uuid]).catch(() => {});
        }

        // Se profili non ha nome ma user_metadata sì, sincronizza (cliente appena registrato)
        let nome = u.nome;
        let cognome = u.cognome;
        if (!nome && userData.user_metadata?.nome) {
            nome = userData.user_metadata.nome;
            cognome = userData.user_metadata.cognome || null;
            pool.query('UPDATE profili SET nome=$1, cognome=$2 WHERE id=$3', [nome, cognome, uuid]).catch(() => {});
        }

        const utente = {
            id: uuid,
            uuid,
            email: userData.email,
            barbiere_id: u.barbiere_id,
            nome,
            cognome,
            telefono,
            ruolo: u.ruolo,
        };

        // Salva in cache per 5 minuti (il token Supabase dura 1 ora, quindi è sicuro)
        tokenCache.set(token, { utente, scadenza: Date.now() + 5 * 60 * 1000 });

        req.utente = utente;
        next();
    } catch (err) {
        return res.status(401).json({ error: "Token non valido o scaduto" });
    }
};

const soloAdmin = (req, res, next) => {
    if (req.utente.ruolo !== 'admin' && req.utente.ruolo !== 'super_admin') {
        return res.status(403).json({ error: "Accesso riservato ai barbieri" });
    }
    next();
};

// Staff di fiducia: ogni admin gestisce le prenotazioni di tutti i barbieri.
// Assenze e permessi (che cancellano appuntamenti e notificano i clienti) restano
// limitati al proprio barbiere; solo il titolare (super_admin) li gestisce per tutti.
const puoGestireAssenze = (utente, barbiereId) =>
    utente.ruolo === 'super_admin' ||
    (utente.barbiere_id != null && Number(barbiereId) === utente.barbiere_id);

const vietato = (res) => res.status(403).json({ error: "Puoi gestire solo le tue assenze e i tuoi permessi" });

// ==========================================
// ASSENZE E PERMESSI (tabella assenze: N record per barbiere)
// ==========================================
// tipo 'assente':  giornate intere da data_inizio a data_fine (NULL = senza fine)
// tipo 'permesso': fascia [ora_inizio, ora_fine) nel giorno data_inizio (= data_fine)
const minuti = (hhmm) => { const [h, m] = String(hhmm).slice(0, 5).split(':').map(Number); return h * 60 + m; };
const hhmm = (min) => `${String(Math.floor(min / 60)).padStart(2, '0')}:${String(min % 60).padStart(2, '0')}`;

// pg restituisce le colonne DATE come oggetti Date (mezzanotte locale)
const dataStr = (d) => typeof d === 'string'
    ? d.slice(0, 10)
    : `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;

// Data e ora correnti in Italia (il server gira in UTC)
const oraItalia = () => {
    const adesso = new Date().toLocaleString('sv-SE', { timeZone: 'Europe/Rome' }).replace(' ', 'T');
    return { data: adesso.slice(0, 10), ora: adesso.slice(11, 16) };
};

const GIORNI = ['Domenica', 'Lunedì', 'Martedì', 'Mercoledì', 'Giovedì', 'Venerdì', 'Sabato'];
const MESI = ['Gennaio', 'Febbraio', 'Marzo', 'Aprile', 'Maggio', 'Giugno', 'Luglio', 'Agosto', 'Settembre', 'Ottobre', 'Novembre', 'Dicembre'];
const fmtData = (d) => {
    const [y, m, g] = dataStr(d).split('-').map(Number);
    const x = new Date(y, m - 1, g);
    return `${GIORNI[x.getDay()]} ${x.getDate()} ${MESI[x.getMonth()]}`;
};

const COLONNE_ASSENZA = `id, barbiere_id, tipo, data_inizio::text AS data_inizio, data_fine::text AS data_fine,
    to_char(ora_inizio, 'HH24:MI') AS ora_inizio, to_char(ora_fine, 'HH24:MI') AS ora_fine, motivo`;

// Assenze/permessi che toccano una data, raggruppati per barbiere
const assenzeDelGiorno = async (db, barbiereIds, data) => {
    const ids = barbiereIds.map(Number);
    const perBarbiere = new Map(ids.map((id) => [id, []]));
    if (ids.length === 0) return perBarbiere;
    const r = await db.query(
        `SELECT ${COLONNE_ASSENZA} FROM assenze
         WHERE barbiere_id = ANY($1::int[]) AND data_inizio <= $2::date AND COALESCE(data_fine, 'infinity') >= $2::date`,
        [ids, data]
    );
    for (const a of r.rows) perBarbiere.get(a.barbiere_id)?.push(a);
    return perBarbiere;
};

// Da tutte le assenze/permessi di un giorno: assente tutto il giorno? E le fasce [inizio, fine)
// in minuti di OGNI permesso (possono essere più di uno nello stesso giorno)
const indisponibilita = (assenze = []) => ({
    giornoIntero: assenze.some((a) => a.tipo === 'assente'),
    finestre: assenze.filter((a) => a.tipo === 'permesso').map((a) => [minuti(a.ora_inizio), minuti(a.ora_fine)]),
});

// Lo slot [ora, ora + durata servizio) non cade in un'assenza o in un permesso?
const slotDisponibile = async (db, barbiereId, data, ora, servizioId) => {
    const b = await db.query('SELECT 1 FROM barbieri WHERE id = $1', [barbiereId]);
    if (b.rows.length === 0) return false;
    const s = await db.query('SELECT durata_minuti FROM servizi WHERE id = $1', [servizioId]);
    const durata = s.rows[0]?.durata_minuti || 40;
    const assenze = (await assenzeDelGiorno(db, [barbiereId], dataStr(data))).get(Number(barbiereId));
    const { giornoIntero, finestre } = indisponibilita(assenze);
    if (giornoIntero) return false;
    const inizio = minuti(ora);
    const fine = inizio + durata;
    return !finestre.some(([a, z]) => inizio < z && fine > a);
};

const nonDisponibile = (res) => res.status(409).json({ error: "Il barbiere non è disponibile in questo orario (assenza o permesso)" });

const descriviAssenza = (a) => {
    if (a.tipo === 'permesso') return `un permesso ${fmtData(a.data_inizio)} dalle ${a.ora_inizio} alle ${a.ora_fine}`;
    return a.data_fine
        ? `un'assenza dal ${fmtData(a.data_inizio)} al ${fmtData(a.data_fine)}`
        : `un'assenza dal ${fmtData(a.data_inizio)} senza data di fine`;
};

// Un'assenza/permesso nuovo si sovrappone a uno già registrato per lo stesso barbiere?
// Un'assenza intera non può coesistere con nulla nelle stesse date; due permessi sì,
// purché gli orari non si accavallino.
const trovaSovrapposizione = async (db, nuova) => {
    const r = await db.query(
        `SELECT ${COLONNE_ASSENZA} FROM assenze
         WHERE barbiere_id = $1 AND data_inizio <= COALESCE($3::date, 'infinity') AND COALESCE(data_fine, 'infinity') >= $2::date
         ORDER BY data_inizio, ora_inizio`,
        [nuova.barbiere_id, nuova.data_inizio, nuova.data_fine]
    );
    return r.rows.find((a) =>
        a.tipo === 'assente' || nuova.tipo === 'assente' ||
        (minuti(a.ora_inizio) < minuti(nuova.ora_fine) && minuti(a.ora_fine) > minuti(nuova.ora_inizio))
    ) || null;
};

// Cancella (stato 'cancellato', non elimina) gli appuntamenti futuri che cadono nell'assenza/permesso
// e avvisa i clienti. Restano collegati all'assenza per ripristinarli se viene annullata.
const cancellaPerAssenza = async (db, a) => {
    const { data: oggi, ora } = oraItalia();
    const params = [a.barbiere_id, oggi, ora, a.data_inizio];
    let filtro;
    if (a.tipo === 'assente') {
        filtro = `AND p.data >= $4::date AND p.data <= COALESCE($5::date, 'infinity')`;
        params.push(a.data_fine);
    } else {
        // Permesso: ogni appuntamento che si sovrappone alla fascia, considerando la durata del servizio
        filtro = `AND p.data = $4::date AND p.ora < $5::time
                  AND p.ora + make_interval(mins => COALESCE(sv.durata_minuti, 40)) > $6::time`;
        params.push(a.ora_fine, a.ora_inizio);
    }
    const r = await db.query(
        `SELECT p.id, p.cliente_uuid, p.data, p.ora, b.nome AS barbiere_nome, sv.nome AS servizio_nome
         FROM prenotazioni p
         JOIN barbieri b ON b.id = p.barbiere_id
         JOIN servizi sv ON sv.id = p.servizio_id
         WHERE p.barbiere_id = $1 AND p.stato = 'attivo'
           AND (p.data > $2::date OR (p.data = $2::date AND p.ora >= $3::time)) ${filtro}`,
        params
    );
    const perche = a.tipo === 'permesso' ? 'il barbiere è in permesso' : 'il barbiere non è disponibile';
    let notificati = 0;
    for (const app of r.rows) {
        await db.query("UPDATE prenotazioni SET stato = 'cancellato', cancellata_da_assenza = $2 WHERE id = $1", [app.id, a.id]);
        if (app.cliente_uuid) {
            const messaggio = `Ci scusiamo per il disagio. Il tuo appuntamento di **${fmtData(app.data)}** alle **${String(app.ora).slice(0, 5)}** con **${app.barbiere_nome}** per il servizio di **${app.servizio_nome}** è stato cancellato perché ${perche}.\n\nTi invitiamo a prenotare un nuovo appuntamento.`;
            await db.query('INSERT INTO notifiche (cliente_uuid, messaggio) VALUES ($1, $2)', [app.cliente_uuid, messaggio]);
            notificati++;
        }
    }
    return { cancellati: r.rows.length, notificati };
};

// Annulla un'assenza/permesso: ripristina gli appuntamenti futuri che aveva cancellato
// (se lo slot è ancora libero), avvisa i clienti ed elimina il record.
const annullaAssenza = async (db, a) => {
    const { data: oggi, ora } = oraItalia();
    const r = await db.query(
        `SELECT p.id, p.cliente_uuid, p.data, p.ora, b.nome AS barbiere_nome, sv.nome AS servizio_nome
         FROM prenotazioni p
         JOIN barbieri b ON b.id = p.barbiere_id
         JOIN servizi sv ON sv.id = p.servizio_id
         WHERE p.cancellata_da_assenza = $1 AND p.stato = 'cancellato'
           AND (p.data > $2::date OR (p.data = $2::date AND p.ora >= $3::time))`,
        [a.id, oggi, ora]
    );
    let ripristinati = 0;
    for (const app of r.rows) {
        const u = await db.query(
            `UPDATE prenotazioni p SET stato = 'attivo', cancellata_da_assenza = NULL
             WHERE p.id = $1 AND NOT EXISTS (
                 SELECT 1 FROM prenotazioni q
                 WHERE q.barbiere_id = p.barbiere_id AND q.data = p.data AND q.ora = p.ora AND q.stato = 'attivo')`,
            [app.id]
        );
        if (u.rowCount === 0) continue;
        ripristinati++;
        if (app.cliente_uuid) {
            const messaggio = `Buone notizie! Il tuo appuntamento di **${fmtData(app.data)}** alle **${String(app.ora).slice(0, 5)}** con **${app.barbiere_nome}** per il servizio di **${app.servizio_nome}** è stato ripristinato. Il barbiere è nuovamente disponibile.\n\nTi aspettiamo!`;
            await db.query('INSERT INTO notifiche (cliente_uuid, messaggio) VALUES ($1, $2)', [app.cliente_uuid, messaggio]);
        }
    }
    await db.query('DELETE FROM assenze WHERE id = $1', [a.id]);
    return ripristinati;
};

// ==========================================
// CRON JOB - Pulizia ogni 10 minuti
// ==========================================
cron.schedule('*/10 * * * *', async () => {
    try {
        const cancellati = await pool.query("DELETE FROM prenotazioni WHERE stato = 'cancellato' AND data < CURRENT_DATE");
        const passati = await pool.query("DELETE FROM prenotazioni WHERE data < CURRENT_DATE AND stato = 'attivo'");
        const totale = (cancellati.rowCount || 0) + (passati.rowCount || 0);
        if (totale > 0) console.log(`Pulizia: eliminati ${totale} appuntamenti`);

        // Assenze e permessi ormai conclusi. Non serve "attivarli": gli appuntamenti
        // vengono cancellati nel momento in cui l'assenza/permesso viene registrato.
        const scadute = await pool.query(
            `DELETE FROM assenze WHERE COALESCE(data_fine, 'infinity') < $1::date`,
            [oraItalia().data]
        );
        if (scadute.rowCount > 0) console.log(`Pulizia: eliminate ${scadute.rowCount} assenze/permessi conclusi`);
    } catch (err) {
        console.error('Errore pulizia:', err);
    }
});

// ==========================================
// AUTH (login/registrazione gestiti da Supabase Auth lato client)
// ==========================================

// Verifica token (per auto-login)
app.get('/api/auth/me', verificaToken, async (req, res) => {
    try {
        res.json({ utente: req.utente });
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// Modifica profilo (clienti e staff). I campi non inviati restano invariati.
app.patch('/api/auth/profilo', verificaToken, async (req, res) => {
    const pulisci = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : null);
    const nome = pulisci(req.body.nome, 50);
    const cognome = pulisci(req.body.cognome, 50);
    const telefono = pulisci(req.body.telefono, 20);
    if (nome === '') return res.status(400).json({ error: "Il nome non può essere vuoto" });

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const result = await client.query(
            `UPDATE profili SET nome = COALESCE($1, nome), cognome = COALESCE($2, cognome), telefono = COALESCE($3, telefono)
             WHERE id = $4 RETURNING nome, cognome`,
            [nome, cognome, telefono, req.utente.uuid]
        );
        const aggiornato = result.rows[0];

        if (req.utente.ruolo === 'cliente') {
            // Aggiorna anche il nome mostrato nelle prenotazioni attive
            const nomeCompleto = [aggiornato.nome, aggiornato.cognome].filter(Boolean).join(' ').trim();
            await client.query(
                "UPDATE prenotazioni SET cliente_nome = $1 WHERE cliente_uuid = $2 AND stato = 'attivo'",
                [nomeCompleto, req.utente.uuid]
            );
        } else if (req.utente.barbiere_id && nome) {
            // Nome del barbiere mostrato ai clienti
            await client.query('UPDATE barbieri SET nome = $1 WHERE id = $2', [nome, req.utente.barbiere_id]);
        }
        await client.query('COMMIT');
        tokenCache.delete(req.token); // i dati in cache sono cambiati
        res.json({ success: true, nome: aggiornato.nome, cognome: aggiornato.cognome });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Errore aggiornamento profilo:", err.message);
        res.status(500).json({ error: "Errore aggiornamento profilo" });
    } finally {
        client.release();
    }
});

// Cambia password (solo staff: i clienti accedono con codice OTP via email)
app.patch('/api/auth/cambia-password', verificaToken, async (req, res) => {
    const { vecchia_password, nuova_password } = req.body;
    if (!vecchia_password || !nuova_password) return res.status(400).json({ error: "Compila tutti i campi" });
    if (typeof nuova_password !== 'string' || nuova_password.length < 6) return res.status(400).json({ error: "Minimo 6 caratteri" });
    if (req.utente.ruolo === 'cliente') {
        return res.status(400).json({ error: "Accedi con il codice via email: non hai una password da cambiare" });
    }

    const authUrl = `${process.env.SUPABASE_URL}/auth/v1`;
    const headers = { apikey: process.env.SUPABASE_ANON_KEY, 'Content-Type': 'application/json' };
    try {
        // 1. Verifica la password attuale con un login: la sessione appena creata
        //    soddisfa anche il requisito di "login recente" di Supabase
        const login = await fetch(`${authUrl}/token?grant_type=password`, {
            method: 'POST', headers,
            body: JSON.stringify({ email: req.utente.email, password: vecchia_password }),
        });
        if (!login.ok) return res.status(401).json({ error: "Password attuale errata" });
        const { access_token } = await login.json();
        const authHeaders = { ...headers, Authorization: `Bearer ${access_token}` };

        // 2. Imposta la nuova password
        const update = await fetch(`${authUrl}/user`, {
            method: 'PUT', headers: authHeaders,
            body: JSON.stringify({ password: nuova_password }),
        });

        // 3. Chiude la sessione temporanea usata per la verifica
        fetch(`${authUrl}/logout?scope=local`, { method: 'POST', headers: authHeaders }).catch(() => {});

        if (!update.ok) {
            const e = await update.json().catch(() => ({}));
            return res.status(400).json({ error: e.msg || e.error_description || "Impossibile aggiornare la password" });
        }
        res.json({ success: true });
    } catch (err) {
        console.error("Errore cambio password:", err.message);
        res.status(500).json({ error: "Errore cambio password" });
    }
});

// ==========================================
// API: SEDI
// ==========================================
app.get('/api/sedi', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM sedi');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore del server" });
    }
});

// ==========================================
// API: SERVIZI
// ==========================================
app.get('/api/servizi', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM servizi ORDER BY prezzo ASC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore nel recupero servizi" });
    }
});

// ==========================================
// API: BARBIERI
// ==========================================
app.get('/api/barbieri/:sede_id', async (req, res) => {
    const { sede_id } = req.params;
    try {
        const result = await pool.query(
            `SELECT DISTINCT b.id, b.nome FROM barbieri b
             JOIN turni_rotazione t ON b.id = t.barbiere_id
             WHERE t.sede_id = $1`,
            [sede_id]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore nel recupero barbieri" });
    }
});

app.get('/api/barbieri-disponibili', async (req, res) => {
    const { sede_id, data } = req.query;
    if (!sede_id || !data) return res.status(400).json({ error: "Mancano parametri" });

    try {
        const dateObj = new Date(data);
        const giorno_settimana = dateObj.getDay();
        if (giorno_settimana === 0 || giorno_settimana === 1) return res.json({ messaggio: "Il negozio è chiuso di Domenica e Lunedì", barbieri: [] });

        const result = await pool.query(
            `SELECT b.id, b.nome FROM barbieri b
             JOIN turni_rotazione t ON b.id = t.barbiere_id
             WHERE t.sede_id = $1 AND t.giorno_settimana = $2`,
            [sede_id, giorno_settimana]
        );
        // Disabilitato = assente per l'intera giornata richiesta. I permessi bloccano solo
        // le loro fasce orarie, escluse da /api/orari-disponibili.
        const assenze = await assenzeDelGiorno(pool, result.rows.map((b) => b.id), data);
        const rows = result.rows.map((b) => {
            const { giornoIntero } = indisponibilita(assenze.get(b.id));
            return { id: b.id, nome: b.nome, assente: giornoIntero, disabilitato: giornoIntero };
        });
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: "Errore durante la ricerca dei barbieri" });
    }
});

// ==========================================
// API: ORARI DISPONIBILI
// ==========================================
app.get('/api/orari-disponibili', async (req, res) => {
    const { barbiere_id, data, servizio_id } = req.query;
    if (!barbiere_id || !data) return res.status(400).json({ error: "Mancano parametri" });

    try {
        const dateObj = new Date(data);
        const giorno = dateObj.getDay();
        
        const fasce = giorno === 4
            ? [[720, 1320]]
            : [[540, 720], [900, 1140]];

        let durataServizio = 40;
        if (servizio_id) {
            const servResult = await pool.query('SELECT durata_minuti FROM servizi WHERE id = $1', [servizio_id]);
            if (servResult.rows.length > 0) durataServizio = servResult.rows[0].durata_minuti;
        }

        const occupati = await pool.query(
            `SELECT p.ora, COALESCE(s.durata_minuti, 40) as durata 
             FROM prenotazioni p 
             LEFT JOIN servizi s ON p.servizio_id = s.id 
             WHERE p.barbiere_id = $1 AND p.data = $2 AND p.stato = 'attivo'
             ORDER BY p.ora ASC`,
            [barbiere_id, data]
        );

        const intervalliOccupati = occupati.rows.map(row => {
            const [h, m] = row.ora.split(':').map(Number);
            const inizio = h * 60 + m;
            return { inizio, fine: inizio + row.durata };
        });

        // Assenze e permessi: giornata intera = nessuno slot, OGNI permesso del giorno = fascia occupata
        const esiste = await pool.query('SELECT 1 FROM barbieri WHERE id = $1', [barbiere_id]);
        if (esiste.rows.length === 0) return res.json([]);
        const assenze = (await assenzeDelGiorno(pool, [barbiere_id], data)).get(Number(barbiere_id));
        const { giornoIntero, finestre } = indisponibilita(assenze);
        if (giornoIntero) return res.json([]);
        for (const [inizio, fine] of finestre) intervalliOccupati.push({ inizio, fine });

        // Costruisci gli slot disponibili partendo dagli spazi liberi
        const disponibili = [];
        
        for (const fascia of fasce) {
            let cursore = fascia[0];
            
            while (cursore + durataServizio <= fascia[1]) {
                const slotFine = cursore + durataServizio;
                
                // Controlla se questo slot si sovrappone con qualche appuntamento
                const overlap = intervalliOccupati.some(occ => 
                    cursore < occ.fine && slotFine > occ.inizio
                );
                
                if (!overlap) {
                    disponibili.push(cursore);
                    // Salta avanti della durata del servizio (non 20 min)
                    cursore += durataServizio;
                } else {
                    // Trova la fine dell'appuntamento che blocca e parti da lì
                    const bloccante = intervalliOccupati.find(occ => 
                        cursore < occ.fine && slotFine > occ.inizio
                    );
                    cursore = bloccante ? bloccante.fine : cursore + 20;
                }
            }
        }

        // Filtra orari passati se è oggi (usa ora italiana)
        let result = disponibili;
        const adesso = new Date(new Date().toLocaleString('en-US', { timeZone: 'Europe/Rome' }));
        const oggi = adesso.toISOString().split('T')[0];
        if (data === oggi) {
            const oraAttuale = adesso.getHours() * 60 + adesso.getMinutes();
            result = disponibili.filter(slot => slot > oraAttuale);
        }

        const orariFinali = result.map(slot => {
            const h = Math.floor(slot / 60).toString().padStart(2, '0');
            const m = (slot % 60).toString().padStart(2, '0');
            return `${h}:${m}`;
        });

        res.json(orariFinali);
    } catch (err) {
        console.error("Errore orari:", err);
        res.status(500).json({ error: "Errore nel recupero orari" });
    }
});

// ==========================================
// API: PRENOTAZIONI (CLIENTI)
// ==========================================

// Crea prenotazione (ora richiede auth)
app.post('/api/prenotazioni', verificaToken, async (req, res) => {
    const { sede_id, barbiere_id, data, ora, servizio_id } = req.body;
    const cliente_nome = [req.utente.nome, req.utente.cognome].filter(Boolean).join(' ').trim() || req.utente.nome;

    if (!sede_id || !barbiere_id || !data || !ora || !servizio_id) {
        return res.status(400).json({ error: "Mancano campi obbligatori" });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const check = await client.query(
            "SELECT id FROM prenotazioni WHERE barbiere_id = $1 AND data = $2 AND ora = $3 AND stato = 'attivo'",
            [barbiere_id, data, ora]
        );
        if (check.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: "Questo orario è già prenotato!" });
        }
        if (!(await slotDisponibile(client, barbiere_id, data, ora, servizio_id))) {
            await client.query('ROLLBACK');
            return nonDisponibile(res);
        }
        const result = await client.query(
            `INSERT INTO prenotazioni (sede_id, barbiere_id, cliente_nome, cliente_uuid, data, ora, servizio_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
            [sede_id, barbiere_id, cliente_nome, req.utente.ruolo === 'cliente' ? req.utente.uuid : null, data, ora, servizio_id]
        );
        await client.query('COMMIT');
        res.json({ success: true, prenotazione: result.rows[0] });
    } catch (err) {
        await client.query('ROLLBACK');
        if (err.code === '23505') {
            return res.status(409).json({ error: "Questo orario è già prenotato!" });
        }
        console.error("Errore salvataggio:", err);
        res.status(500).json({ error: "Errore nel salvataggio della prenotazione" });
    } finally {
        client.release();
    }
});

// I miei appuntamenti
app.get('/api/prenotazioni/miei', verificaToken, async (req, res) => {
    const { sede_id } = req.query;
    const cliente_uuid = req.utente.uuid;

    try {
        const italianNow = new Date().toLocaleString('sv-SE', { timeZone: 'Europe/Rome' }).replace(' ', 'T');
        const oggi = italianNow.slice(0, 10);
        const italianTime = italianNow.slice(11, 16);

        let query = `
            SELECT p.id, p.data, p.ora, p.stato, p.sede_id,
                    s.nome AS sede_nome, b.nome AS barbiere_nome,
                    sv.nome AS servizio_nome, sv.prezzo AS servizio_prezzo
             FROM prenotazioni p
             JOIN sedi s ON p.sede_id = s.id
             JOIN barbieri b ON p.barbiere_id = b.id
             JOIN servizi sv ON p.servizio_id = sv.id
             WHERE p.cliente_uuid = $1 AND p.stato IN ('attivo', 'cancellato')
             AND (p.data > $2::date OR (p.data = $2::date AND p.ora >= $3::time))`;
        const params = [cliente_uuid, oggi, italianTime];

        if (sede_id) { query += ` AND p.sede_id = $4`; params.push(sede_id); }
        query += ` ORDER BY p.data ASC, p.ora ASC`;

        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore nel recupero delle prenotazioni" });
    }
});

// Cancella prenotazione (cliente) — solo le proprie
app.delete('/api/prenotazioni/:id', verificaToken, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query(
            "DELETE FROM prenotazioni WHERE id = $1 AND cliente_uuid = $2 AND stato = 'attivo' RETURNING id", [id, req.utente.uuid]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: "Non trovata o già cancellata" });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Errore nella cancellazione" });
    }
});

// Notifiche cliente
app.get('/api/notifiche', verificaToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM notifiche WHERE cliente_uuid = $1 ORDER BY created_at DESC LIMIT 20',
            [req.utente.uuid]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

app.patch('/api/notifiche/lette', verificaToken, async (req, res) => {
    try {
        await pool.query('UPDATE notifiche SET letta = true WHERE cliente_uuid = $1', [req.utente.uuid]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// ==========================================
// API: ADMIN (BARBIERI)
// ==========================================

// Tutte le prenotazioni per sede + data
app.get('/api/admin/prenotazioni', verificaToken, soloAdmin, async (req, res) => {
    const { sede_id, data, barbiere_id } = req.query;
    const dataQuery = data || new Date().toISOString().split('T')[0];
    if (!sede_id) return res.status(400).json({ error: "Manca sede_id" });

    try {
        let query = `
            SELECT p.id, p.data, p.ora, p.stato, p.servizio_id, p.cliente_uuid,
             CASE WHEN pr.nome IS NOT NULL
               THEN TRIM(pr.nome || ' ' || COALESCE(pr.cognome, ''))
               ELSE p.cliente_nome
             END AS cliente_nome,
             b.nome AS barbiere_nome, b.id AS barbiere_id,
             sv.nome AS servizio_nome, sv.prezzo AS servizio_prezzo, sv.durata_minuti,
             COALESCE(p.cliente_telefono, pr.telefono) AS cliente_telefono
             FROM prenotazioni p
             JOIN barbieri b ON p.barbiere_id = b.id
             JOIN servizi sv ON p.servizio_id = sv.id
             LEFT JOIN profili pr ON pr.id = p.cliente_uuid
             WHERE p.sede_id = $1 AND p.data = $2`;
        const params = [sede_id, dataQuery];

        if (barbiere_id) {
            query += ` AND p.barbiere_id = $3`;
            params.push(barbiere_id);
        }
        query += ` ORDER BY p.ora ASC`;

        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// Prenotazioni settimana
app.get('/api/admin/prenotazioni/settimana', verificaToken, soloAdmin, async (req, res) => {
    const { sede_id, data_inizio } = req.query;
    if (!sede_id) return res.status(400).json({ error: "Manca sede_id" });

    let inizio;
    if (data_inizio) { inizio = new Date(data_inizio); }
    else { inizio = new Date(); const day = inizio.getDay(); inizio.setDate(inizio.getDate() - (day === 0 ? 6 : day - 1)); }
    const fine = new Date(inizio); fine.setDate(fine.getDate() + 6);

    try {
        const result = await pool.query(
            `SELECT p.id, p.data, p.ora, p.stato, p.servizio_id, p.cliente_uuid,
             CASE WHEN pr.nome IS NOT NULL
               THEN TRIM(pr.nome || ' ' || COALESCE(pr.cognome, ''))
               ELSE p.cliente_nome
             END AS cliente_nome,
             b.nome AS barbiere_nome, b.id AS barbiere_id,
             sv.nome AS servizio_nome, sv.prezzo AS servizio_prezzo, sv.durata_minuti
             FROM prenotazioni p
             JOIN barbieri b ON p.barbiere_id = b.id
             JOIN servizi sv ON p.servizio_id = sv.id
             LEFT JOIN profili pr ON pr.id = p.cliente_uuid
             WHERE p.sede_id = $1 AND p.data BETWEEN $2 AND $3 ORDER BY p.data ASC, p.ora ASC`,
            [sede_id, inizio.toISOString().split('T')[0], fine.toISOString().split('T')[0]]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// Aggiungi prenotazione (admin)
app.post('/api/admin/prenotazioni', verificaToken, soloAdmin, async (req, res) => {
    const { sede_id, barbiere_id, cliente_nome, cliente_telefono, data, ora, servizio_id } = req.body;
    if (!sede_id || !barbiere_id || !cliente_nome || !data || !ora || !servizio_id) {
        return res.status(400).json({ error: "Mancano campi obbligatori" });
    }
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const check = await client.query(
            "SELECT id FROM prenotazioni WHERE barbiere_id = $1 AND data = $2 AND ora = $3 AND stato = 'attivo'",
            [barbiere_id, data, ora]
        );
        if (check.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: "Orario già prenotato!" });
        }
        if (!(await slotDisponibile(client, barbiere_id, data, ora, servizio_id))) {
            await client.query('ROLLBACK');
            return nonDisponibile(res);
        }
        const result = await client.query(
            `INSERT INTO prenotazioni (sede_id, barbiere_id, cliente_nome, cliente_telefono, data, ora, servizio_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
            [sede_id, barbiere_id, cliente_nome, cliente_telefono || null, data, ora, servizio_id]
        );
        await client.query('COMMIT');
        res.json({ success: true, prenotazione: result.rows[0] });
    } catch (err) {
        await client.query('ROLLBACK');
        if (err.code === '23505') {
            return res.status(409).json({ error: "Orario già prenotato!" });
        }
        res.status(500).json({ error: "Errore nel salvataggio" });
    } finally {
        client.release();
    }
});

// Modifica prenotazione (admin)
app.patch('/api/admin/prenotazioni/:id', verificaToken, soloAdmin, async (req, res) => {
    const { id } = req.params;
    const { ora, barbiere_id, data } = req.body;
    try {
        const pren = await pool.query('SELECT * FROM prenotazioni WHERE id = $1', [id]);
        if (pren.rows.length === 0) return res.status(404).json({ error: "Non trovata" });
        const p = pren.rows[0];
        const newOra = ora || p.ora, newBarbiere = barbiere_id || p.barbiere_id, newData = data || p.data;

        const check = await pool.query(
            "SELECT id FROM prenotazioni WHERE barbiere_id=$1 AND data=$2 AND ora=$3 AND stato='attivo' AND id!=$4",
            [newBarbiere, newData, newOra, id]
        );
        if (check.rows.length > 0) return res.status(409).json({ error: "Nuovo orario già occupato!" });
        if (!(await slotDisponibile(pool, newBarbiere, newData, newOra, p.servizio_id))) return nonDisponibile(res);

        const result = await pool.query(
            `UPDATE prenotazioni SET ora=$1, barbiere_id=$2, data=$3 WHERE id=$4 AND stato='attivo' RETURNING *`,
            [newOra, newBarbiere, newData, id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: "Non modificabile" });
        res.json({ success: true, prenotazione: result.rows[0] });
    } catch (err) {
        res.status(500).json({ error: "Errore nella modifica" });
    }
});

// Cancella prenotazione (admin)
app.delete('/api/admin/prenotazioni/:id', verificaToken, soloAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query("DELETE FROM prenotazioni WHERE id = $1 RETURNING id", [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: "Non trovata" });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// Lista barbieri (admin), ognuno con le sue assenze/permessi in corso e futuri
app.get('/api/admin/barbieri', verificaToken, soloAdmin, async (req, res) => {
    const { sede_id } = req.query;
    try {
        let result;
        if (sede_id) {
            result = await pool.query(
                `SELECT b.id, b.nome, b.tipo,
                        array_agg(t.giorno_settimana ORDER BY t.giorno_settimana) AS giorni_lavoro
                 FROM barbieri b
                 JOIN turni_rotazione t ON b.id=t.barbiere_id
                 WHERE t.sede_id=$1
                 GROUP BY b.id, b.nome, b.tipo
                 ORDER BY b.nome`, [sede_id]
            );
        } else {
            result = await pool.query('SELECT id, nome, tipo FROM barbieri ORDER BY nome');
        }
        const ids = result.rows.map((b) => b.id);
        const assenze = ids.length === 0 ? { rows: [] } : await pool.query(
            `SELECT ${COLONNE_ASSENZA} FROM assenze
             WHERE barbiere_id = ANY($1::int[]) AND COALESCE(data_fine, 'infinity') >= $2::date
             ORDER BY data_inizio, ora_inizio NULLS FIRST`,
            [ids, oraItalia().data]
        );
        res.json(result.rows.map((b) => ({ ...b, assenze: assenze.rows.filter((a) => a.barbiere_id === b.id) })));
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// Registra una nuova assenza/permesso: sempre un nuovo record (INSERT), rifiutato solo se si
// sovrappone a uno esistente. Gli appuntamenti futuri nel periodo vengono cancellati subito.
const registraAssenza = async (res, nuova, motivo) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        // Serializza le scritture sulle assenze dello stesso barbiere (due inserimenti paralleli sovrapposti)
        await client.query('SELECT pg_advisory_xact_lock($1::bigint)', [nuova.barbiere_id]);
        const conflitto = await trovaSovrapposizione(client, nuova);
        if (conflitto) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: `Questo barbiere ha già ${descriviAssenza(conflitto)}: gli orari si sovrappongono.` });
        }
        const ins = await client.query(
            `INSERT INTO assenze (barbiere_id, tipo, data_inizio, data_fine, ora_inizio, ora_fine, motivo)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING ${COLONNE_ASSENZA}`,
            [nuova.barbiere_id, nuova.tipo, nuova.data_inizio, nuova.data_fine, nuova.ora_inizio || null, nuova.ora_fine || null, motivo || null]
        );
        const assenza = ins.rows[0];
        const { cancellati, notificati } = await cancellaPerAssenza(client, assenza);
        await client.query('COMMIT');
        const cosa = assenza.tipo === 'permesso' ? 'Permesso registrato' : 'Assenza registrata';
        res.json({
            success: true,
            assenza,
            eliminati: cancellati,
            notifiche_inviate: notificati,
            messaggio: cancellati > 0
                ? `${cosa}. ${cancellati} appuntamenti cancellati e ${notificati} clienti notificati.`
                : `${cosa}.`,
        });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Errore registrazione assenza:", err.message);
        res.status(500).json({ error: "Errore nel salvataggio dell'assenza/permesso" });
    } finally {
        client.release();
    }
};

const DATA_RE = /^\d{4}-\d{2}-\d{2}$/;
const ORA_RE = /^\d{2}:\d{2}$/;

// ASSENZA (giornate intere, con data e durata in giorni opzionale; senza durata = senza fine)
app.post('/api/admin/barbiere-assente', verificaToken, soloAdmin, async (req, res) => {
    const { barbiere_id, motivo, data_inizio, giorni } = req.body;
    if (!barbiere_id) return res.status(400).json({ error: "Manca barbiere_id" });
    if (!puoGestireAssenze(req.utente, barbiere_id)) return vietato(res);

    const inizio = data_inizio || oraItalia().data;
    if (!DATA_RE.test(inizio)) return res.status(400).json({ error: "Data non valida" });
    let fine = null;
    if (giorni && giorni > 0) {
        const d = new Date(inizio + 'T12:00:00Z');
        d.setUTCDate(d.getUTCDate() + Number(giorni) - 1);
        fine = d.toISOString().slice(0, 10);
    }
    return registraAssenza(res, { barbiere_id: Number(barbiere_id), tipo: 'assente', data_inizio: inizio, data_fine: fine }, motivo || 'Assente');
});

// PERMESSO (fascia oraria in un giorno: data, ora di inizio e durata in minuti)
app.post('/api/admin/barbiere-permesso', verificaToken, soloAdmin, async (req, res) => {
    const { barbiere_id, data_inizio, ora_inizio, minuti: durata } = req.body;
    if (!barbiere_id || !durata) return res.status(400).json({ error: "Manca barbiere_id o minuti" });
    if (!puoGestireAssenze(req.utente, barbiere_id)) return vietato(res);

    const adesso = oraItalia();
    const dataI = data_inizio || adesso.data;
    const oraI = ora_inizio || adesso.ora;
    if (!DATA_RE.test(dataI) || !ORA_RE.test(oraI)) return res.status(400).json({ error: "Data o ora non valida" });
    const durataMin = parseInt(durata, 10);
    const fineMin = minuti(oraI) + durataMin;
    if (!(durataMin > 0)) return res.status(400).json({ error: "Durata non valida" });
    if (fineMin > 24 * 60) return res.status(400).json({ error: "Il permesso deve terminare entro la mezzanotte" });

    return registraAssenza(res, {
        barbiere_id: Number(barbiere_id), tipo: 'permesso',
        data_inizio: dataI, data_fine: dataI, ora_inizio: oraI, ora_fine: hhmm(fineMin),
    });
});

// ANNULLA una singola assenza/permesso (ripristina gli appuntamenti che aveva cancellato)
app.delete('/api/admin/assenze/:id', verificaToken, soloAdmin, async (req, res) => {
    if (!/^\d+$/.test(req.params.id)) return res.status(404).json({ error: "Non trovata" });
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const r = await client.query(`SELECT ${COLONNE_ASSENZA} FROM assenze WHERE id = $1 FOR UPDATE`, [req.params.id]);
        if (r.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: "Non trovata" });
        }
        const a = r.rows[0];
        if (!puoGestireAssenze(req.utente, a.barbiere_id)) {
            await client.query('ROLLBACK');
            return vietato(res);
        }
        const ripristinati = await annullaAssenza(client, a);
        await client.query('COMMIT');
        res.json({
            success: true,
            ripristinati,
            messaggio: `${a.tipo === 'permesso' ? 'Permesso annullato' : 'Assenza annullata'}. ${ripristinati} appuntamenti ripristinati.`,
        });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Errore annullamento assenza:", err.message);
        res.status(500).json({ error: "Errore" });
    } finally {
        client.release();
    }
});

// RIATTIVA BARBIERE: annulla le assenze/permessi in corso oggi (compatibilità con la vecchia dashboard)
app.post('/api/admin/barbiere-presente', verificaToken, soloAdmin, async (req, res) => {
    const { barbiere_id } = req.body;
    if (!barbiere_id) return res.status(400).json({ error: "Manca barbiere_id" });
    if (!puoGestireAssenze(req.utente, barbiere_id)) return vietato(res);
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const r = await client.query(
            `SELECT ${COLONNE_ASSENZA} FROM assenze
             WHERE barbiere_id = $1 AND data_inizio <= $2::date AND COALESCE(data_fine, 'infinity') >= $2::date
             FOR UPDATE`,
            [barbiere_id, oraItalia().data]
        );
        let ripristinati = 0;
        for (const a of r.rows) ripristinati += await annullaAssenza(client, a);
        await client.query('COMMIT');
        res.json({ success: true, messaggio: `Barbiere riattivato. ${ripristinati} appuntamenti ripristinati.`, ripristinati });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: "Errore" });
    } finally {
        client.release();
    }
});
