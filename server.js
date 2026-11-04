const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config();
const cron = require('node-cron');
const rateLimit = require('express-rate-limit');
const { emailConfigurata, inviaEmail } = require('./email');

const app = express();
app.set('trust proxy', 1); // Render sta dietro un proxy: serve per leggere l'IP reale del client
app.use(cors());
app.use(express.json({ limit: '10kb' }));

// Keep-alive: un cron esterno (es. cron-job.org ogni 10 minuti) chiama questa rotta per evitare che
// Render addormenti il servizio (cold start ~30 s). Non tocca il database ed è fuori dal rate limit.
app.get('/api/ping', (req, res) => res.json({ ok: true, ts: Date.now() }));

// Rate limiting per IP: generale su tutte le API + più stretto sulle scritture
app.use('/api', rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false }));
const limiteScritture = rateLimit({
    windowMs: 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false,
    skip: (req) => req.method === 'GET',
    message: { error: "Troppe richieste, riprova tra un minuto" },
});
app.use('/api/prenotazioni', limiteScritture);
app.use('/api/auth', limiteScritture);
app.use('/api/admin/comunicazioni', limiteScritture);
app.use('/api/admin/aperture-straordinarie', limiteScritture);
app.use('/api/admin/orari-sedi', limiteScritture);
app.use('/api/admin/turni', limiteScritture);

// ==========================================
// CONFIGURAZIONE DATABASE
// ==========================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    // Se il database non risponde, la richiesta fallisce dopo 10 s invece di restare appesa
    // (l'app mostrava un caricamento infinito)
    connectionTimeoutMillis: 10000,
});

// Una connessione inattiva chiusa dal database (riavvio/manutenzione del pooler Supabase, rete)
// fa emettere 'error' al pool: senza questo gestore Node termina il processo e Render entra in un
// ciclo di crash (503 su tutte le rotte). Il pool scarta la connessione e alla prossima query ne apre una nuova.
pool.on('error', (err) => {
    console.warn('DB: connessione inattiva persa, il server resta attivo —', err.message);
});

// Ultima rete di sicurezza: un errore non gestito viene registrato nei log senza spegnere il server
process.on('unhandledRejection', (err) => {
    console.error('Promise rifiutata non gestita:', err?.message || err);
});
process.on('uncaughtException', (err) => {
    console.error('Eccezione non gestita:', err?.stack || err);
});

const PORTA = process.env.PORT || 3000;
app.listen(PORTA, () => {
    console.log(`Server avviato sulla porta ${PORTA}`);
    if (!emailConfigurata()) {
        console.warn('Email disattivate: RESEND_API_KEY / EMAIL_MITTENTE non impostate. I messaggi restano solo in app.');
    }
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

// Verifiche in corso per token: le pagine fanno più chiamate in parallelo con lo stesso token
// appena emesso; così Supabase Auth + DB vengono interrogati una volta sola, non una per chiamata.
const verificheInCorso = new Map(); // token → Promise<utente | null>

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

        let verifica = verificheInCorso.get(token);
        if (!verifica) {
            verifica = utenteDaToken(token).finally(() => verificheInCorso.delete(token));
            verificheInCorso.set(token, verifica);
        }
        const utente = await verifica;
        if (!utente) return res.status(401).json({ error: "Token non valido o scaduto" });

        req.utente = utente;
        next();
    } catch (err) {
        return res.status(401).json({ error: "Token non valido o scaduto" });
    }
};

// Utente del token (null se il token non è valido o il profilo non esiste); salva in cache 5 minuti
const utenteDaToken = async (token) => {
    const risposta = await fetch(`${process.env.SUPABASE_URL}/auth/v1/user`, {
        headers: {
            'Authorization': `Bearer ${token}`,
            'apikey': process.env.SUPABASE_ANON_KEY,
        }
    });

    if (!risposta.ok) return null;

    const userData = await risposta.json();
    const uuid = userData.id;

    const result = await pool.query(
        `SELECT p.id, p.ruolo, p.nome, p.cognome, p.telefono, b.id AS barbiere_id
         FROM profili p
         LEFT JOIN barbieri b ON b.profilo_id = p.id
         WHERE p.id = $1`,
        [uuid]
    );

    if (result.rows.length === 0) return null;

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
    return utente;
};

// Ruoli (dal più alto): developer > super_admin (titolare) > admin (barbiere) > cliente
const RUOLI_STAFF = ['admin', 'super_admin', 'developer'];

const soloAdmin = (req, res, next) => {
    if (!RUOLI_STAFF.includes(req.utente.ruolo)) {
        return res.status(403).json({ error: "Accesso riservato ai barbieri" });
    }
    next();
};

// Funzioni riservate al developer: comunicazioni a tutti i clienti e aperture straordinarie.
// Titolare e barbieri ricevono 403 anche chiamando l'API direttamente.
const soloDeveloper = (req, res, next) => {
    if (req.utente.ruolo !== 'developer') {
        return res.status(403).json({ error: "Funzione riservata allo sviluppatore" });
    }
    next();
};

// Staff di fiducia: ogni admin gestisce le prenotazioni di tutti i barbieri.
// Assenze e permessi (che cancellano appuntamenti e notificano i clienti) restano
// limitati al proprio barbiere; il titolare (super_admin) e il developer li gestiscono per tutti.
const puoGestireAssenze = (utente, barbiereId) =>
    utente.ruolo === 'super_admin' || utente.ruolo === 'developer' ||
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

// ==========================================
// GIORNI DI CHIUSURA E APERTURE STRAORDINARIE
// ==========================================
// Orari standard per sede e giorno della settimana nella tabella orari_sedi (modificabili dalla
// Console Developer): un giorno senza fasce è un giorno di chiusura. Le singole date di chiusura
// possono essere sbloccate (tabella aperture_straordinarie: una riga = una data precisa, mai ricorrente).
const DATA_RE = /^\d{4}-\d{2}-\d{2}$/;
const ORA_RE = /^([01]\d|2[0-3]):[0-5]\d$/;
// Giorno della settimana (0=dom … 6=sab) di una data 'YYYY-MM-DD', indipendente dal fuso del server
const giornoDellaSettimana = (data) => {
    const [y, m, g] = dataStr(data).split('-').map(Number);
    return new Date(Date.UTC(y, m - 1, g)).getUTCDay();
};

// Fasce di apertura standard [inizio, fine] in minuti di una sede in un giorno della settimana ([] = chiusa)
const fasceSede = async (db, sedeId, giorno) => {
    const r = await db.query(
        `SELECT to_char(ora_inizio, 'HH24:MI') AS i, to_char(ora_fine, 'HH24:MI') AS f
         FROM orari_sedi WHERE sede_id = $1 AND giorno_settimana = $2 ORDER BY ora_inizio`,
        [sedeId, giorno]
    );
    return r.rows.map((x) => [minuti(x.i), minuti(x.f)]);
};

const COLONNE_APERTURA = `a.id, a.data::text AS data, a.sede_id, s.nome AS sede_nome,
    to_char(a.ora_inizio, 'HH24:MI') AS ora_inizio, to_char(a.ora_fine, 'HH24:MI') AS ora_fine, a.barbieri`;

// L'apertura straordinaria di quella data (per una sede e/o che includa un barbiere), o null
const aperturaStraordinaria = async (db, data, { sedeId = null, barbiereId = null } = {}) => {
    const r = await db.query(
        `SELECT ${COLONNE_APERTURA} FROM aperture_straordinarie a JOIN sedi s ON s.id = a.sede_id
         WHERE a.data = $1::date AND ($2::int IS NULL OR a.sede_id = $2::int)
           AND ($3::int IS NULL OR $3::int = ANY(a.barbieri))
         ORDER BY a.sede_id LIMIT 1`,
        [data, sedeId, barbiereId]
    );
    return r.rows[0] || null;
};

// Fasce prenotabili di un barbiere in una data: quelle dell'apertura straordinaria se quel giorno è
// in servizio, altrimenti l'orario standard della sede del suo turno settimanale. [] = non prenotabile.
// Con sedeId limita la ricerca a quella sede.
const fasceBarbiere = async (db, barbiereId, data, sedeId = null) => {
    const apertura = await aperturaStraordinaria(db, data, { sedeId, barbiereId });
    if (apertura) return [[minuti(apertura.ora_inizio), minuti(apertura.ora_fine)]];
    const giorno = giornoDellaSettimana(data);
    const t = await db.query(
        `SELECT sede_id FROM turni_rotazione
         WHERE barbiere_id = $1 AND giorno_settimana = $2 AND ($3::int IS NULL OR sede_id = $3::int)`,
        [barbiereId, giorno, sedeId]
    );
    if (t.rows.length === 0) return [];
    return fasceSede(db, t.rows[0].sede_id, giorno);
};

// Archivio operazioni del developer (Console Developer → Archivio Operazioni / Esporta Report).
// Va chiamata dentro la stessa transazione dell'operazione: si registra solo ciò che è stato salvato.
const registraOperazione = (db, utente, azione, descrizione, dettagli = null) =>
    db.query(
        'INSERT INTO developer_logs (utente_id, azione, descrizione, dettagli) VALUES ($1, $2, $3, $4)',
        [utente.uuid, azione, descrizione, dettagli ? JSON.stringify(dettagli) : null]
    );

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

// ==========================================
// MESSAGGI AI CLIENTI (inbox in-app + email)
// ==========================================
// Ogni messaggio è una riga di notifiche (visibile in "Messaggi") e, se l'email è configurata,
// viene inviato anche all'indirizzo di login del cliente (auth.users.email).
const OGGETTO_EMAIL = {
    cancellazione: 'Il tuo appuntamento è stato cancellato',
    ripristino: 'Il tuo appuntamento è stato ripristinato',
};
const pausa = (ms) => new Promise((r) => setTimeout(r, ms));

// Inserisce un messaggio nell'inbox del cliente e ne restituisce l'id
const creaNotifica = async (db, { cliente_uuid, tipo, titolo, messaggio, comunicazione_id = null }) => {
    const r = await db.query(
        `INSERT INTO notifiche (cliente_uuid, tipo, titolo, messaggio, comunicazione_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [cliente_uuid, tipo, titolo, messaggio, comunicazione_id]
    );
    return r.rows[0].id;
};

// Invia per email i messaggi indicati, uno alla volta, registrando l'esito su ogni riga.
// Va chiamata DOPO il COMMIT (un'operazione annullata non deve mandare email).
const inviaEmailNotifiche = async (ids) => {
    if (!ids.length) return;
    if (!emailConfigurata()) {
        console.log(`Email non configurata (RESEND_API_KEY / EMAIL_MITTENTE): ${ids.length} messaggi solo in-app`);
        return;
    }
    const r = await pool.query(
        `SELECT n.id, n.tipo, n.titolo, n.messaggio, u.email
         FROM notifiche n JOIN auth.users u ON u.id = n.cliente_uuid
         WHERE n.id = ANY($1::int[]) AND n.email_inviata_at IS NULL AND u.email IS NOT NULL`,
        [ids]
    );
    for (const n of r.rows) {
        const titolo = n.titolo || 'Nuovo messaggio';
        try {
            await inviaEmail({ a: n.email, oggetto: OGGETTO_EMAIL[n.tipo] || titolo, titolo, messaggio: n.messaggio });
            await pool.query('UPDATE notifiche SET email_inviata_at = now(), email_errore = NULL WHERE id = $1', [n.id]);
        } catch (err) {
            console.error(`Email notifica ${n.id} non inviata:`, err.message);
            await pool.query('UPDATE notifiche SET email_errore = $2 WHERE id = $1', [n.id, String(err.message).slice(0, 300)]).catch(() => {});
        }
        await pausa(600); // Resend accetta al massimo ~2 richieste al secondo
    }
};
// In background: la risposta all'app non aspetta l'invio delle email
const programmaEmail = (ids) => {
    inviaEmailNotifiche(ids).catch((err) => console.error('Invio email notifiche:', err.message));
};

// Cancella (stato 'cancellato', non elimina) gli appuntamenti futuri che cadono nell'assenza/permesso
// e avvisa i clienti. Restano collegati all'assenza per ripristinarli se viene annullata.
// Restituisce anche gli id dei messaggi creati, da inviare per email dopo il COMMIT.
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
    const notifiche = [];
    for (const app of r.rows) {
        await db.query("UPDATE prenotazioni SET stato = 'cancellato', cancellata_da_assenza = $2 WHERE id = $1", [app.id, a.id]);
        if (app.cliente_uuid) {
            const messaggio = `Ci scusiamo per il disagio. Il tuo appuntamento di **${fmtData(app.data)}** alle **${String(app.ora).slice(0, 5)}** con **${app.barbiere_nome}** per il servizio di **${app.servizio_nome}** è stato cancellato perché ${perche}.\n\nTi invitiamo a prenotare un nuovo appuntamento.`;
            notifiche.push(await creaNotifica(db, { cliente_uuid: app.cliente_uuid, tipo: 'cancellazione', titolo: 'Appuntamento cancellato', messaggio }));
        }
    }
    return { cancellati: r.rows.length, notificati: notifiche.length, notifiche };
};

// Annulla un'assenza/permesso: ripristina gli appuntamenti futuri che aveva cancellato
// (se lo slot è ancora libero), avvisa i clienti ed elimina il record.
// Restituisce quanti appuntamenti sono stati ripristinati e gli id dei messaggi creati.
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
    const notifiche = [];
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
            notifiche.push(await creaNotifica(db, { cliente_uuid: app.cliente_uuid, tipo: 'ripristino', titolo: 'Appuntamento ripristinato', messaggio }));
        }
    }
    await db.query('DELETE FROM assenze WHERE id = $1', [a.id]);
    return { ripristinati, notifiche };
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
        // giorni_lavoro: giorni della settimana (0=dom … 6=sab) in cui il barbiere è in QUESTA sede
        const result = await pool.query(
            `SELECT b.id, b.nome,
                    array_agg(DISTINCT t.giorno_settimana ORDER BY t.giorno_settimana) AS giorni_lavoro
             FROM barbieri b
             JOIN turni_rotazione t ON b.id = t.barbiere_id
             WHERE t.sede_id = $1
             GROUP BY b.id, b.nome
             ORDER BY b.id`,
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

    if (!DATA_RE.test(data)) return res.status(400).json({ error: "Data non valida" });

    try {
        let result;
        const giorno = giornoDellaSettimana(data);
        // Apertura straordinaria di QUESTA data: i barbieri scelti per quel giorno
        const apertura = await aperturaStraordinaria(pool, data, { sedeId: Number(sede_id) });
        if (apertura) {
            result = await pool.query('SELECT id, nome FROM barbieri WHERE id = ANY($1::int[]) ORDER BY id', [apertura.barbieri]);
        } else {
            // Giorno di chiusura della sede secondo l'orario standard
            if ((await fasceSede(pool, Number(sede_id), giorno)).length === 0) {
                return res.json({ messaggio: "La sede è chiusa in questa data", barbieri: [] });
            }
            result = await pool.query(
                `SELECT b.id, b.nome FROM barbieri b
                 JOIN turni_rotazione t ON b.id = t.barbiere_id
                 WHERE t.sede_id = $1 AND t.giorno_settimana = $2`,
                [sede_id, giorno]
            );
        }
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
    if (!DATA_RE.test(data)) return res.status(400).json({ error: "Data non valida" });

    try {
        // Orario standard della sede del suo turno, o la fascia dell'apertura straordinaria
        const fasce = await fasceBarbiere(pool, Number(barbiere_id), data);
        if (fasce.length === 0) return res.json([]);

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
    if (!DATA_RE.test(data) || !ORA_RE.test(String(ora).slice(0, 5))) {
        return res.status(400).json({ error: "Data o orario non validi" });
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
        // L'appuntamento deve stare tutto in una fascia prenotabile: orario standard della sede in cui il
        // barbiere è di turno quel giorno, oppure l'apertura straordinaria di QUESTA data
        {
            const fasce = await fasceBarbiere(client, Number(barbiere_id), data, Number(sede_id));
            const durata = (await client.query('SELECT durata_minuti FROM servizi WHERE id = $1', [servizio_id])).rows[0]?.durata_minuti || 40;
            const inizio = minuti(ora);
            if (!fasce.some(([a, z]) => inizio >= a && inizio + durata <= z)) {
                await client.query('ROLLBACK');
                return res.status(409).json({ error: "La sede è chiusa o il barbiere non è in servizio in questo orario" });
            }
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
            // Solo i campi per l'app (l'esito delle email resta interno)
            `SELECT id, tipo, titolo, messaggio, letta, created_at
             FROM notifiche WHERE cliente_uuid = $1 ORDER BY created_at DESC LIMIT 20`,
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
        const { cancellati, notificati, notifiche } = await cancellaPerAssenza(client, assenza);
        await client.query('COMMIT');
        programmaEmail(notifiche);
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
        const { ripristinati, notifiche } = await annullaAssenza(client, a);
        await client.query('COMMIT');
        programmaEmail(notifiche);
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
        const notifiche = [];
        for (const a of r.rows) {
            const esito = await annullaAssenza(client, a);
            ripristinati += esito.ripristinati;
            notifiche.push(...esito.notifiche);
        }
        await client.query('COMMIT');
        programmaEmail(notifiche);
        res.json({ success: true, messaggio: `Barbiere riattivato. ${ripristinati} appuntamenti ripristinati.`, ripristinati });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: "Errore" });
    } finally {
        client.release();
    }
});

// ==========================================
// COMUNICAZIONI GENERALI (solo developer, es. "Sede chiusa per problemi tecnici")
// ==========================================
// Il messaggio arriva nella sezione Messaggi di ogni destinatario (una riga di notifiche ciascuno,
// con il proprio stato "letto") e, se configurata, via email. Destinatari:
//   cliente_uuid → solo quel cliente
//   sede_id      → i clienti che hanno prenotato almeno una volta in quella sede
//   nessuno dei due → tutti i clienti
const DESTINATARI_SQL = `
    SELECT p.id FROM profili p
    WHERE p.ruolo = 'cliente'
      AND ($1::uuid IS NULL OR p.id = $1::uuid)
      AND ($2::int IS NULL OR EXISTS (
            SELECT 1 FROM prenotazioni pr WHERE pr.cliente_uuid = p.id AND pr.sede_id = $2::int))`;

// Crea la comunicazione e un messaggio per ogni destinatario (dentro la transazione del chiamante).
// Restituisce gli id dei messaggi: dopo il COMMIT vanno passati a programmaEmail.
const creaComunicazione = async (db, { titolo, messaggio, sedeId = null, clienteUuid = null, inviataDa }) => {
    const destinatari = (await db.query(DESTINATARI_SQL, [clienteUuid, sedeId])).rows.map((r) => r.id);
    if (destinatari.length === 0) return { comunicazione: null, notifiche: [], destinatari: 0 };
    const c = await db.query(
        `INSERT INTO comunicazioni (titolo, messaggio, sede_id, inviata_da, destinatari)
         VALUES ($1, $2, $3, $4, $5) RETURNING id, titolo, messaggio, sede_id, destinatari, created_at`,
        [titolo, messaggio, sedeId, inviataDa, destinatari.length]
    );
    const comunicazione = c.rows[0];
    // Una riga per cliente in un'unica query
    const ins = await db.query(
        `INSERT INTO notifiche (cliente_uuid, tipo, titolo, messaggio, comunicazione_id)
         SELECT d, 'comunicazione', $2, $3, $4 FROM unnest($1::uuid[]) AS d RETURNING id`,
        [destinatari, titolo, messaggio, comunicazione.id]
    );
    return { comunicazione, notifiche: ins.rows.map((r) => r.id), destinatari: destinatari.length };
};

const esitoInvio = (n) => `${n} ${n === 1 ? 'cliente' : 'clienti'}`
    + (emailConfigurata() ? ' (in app e via email)' : ' (solo in app: email non configurata)');

// Con anteprima: true non invia nulla e restituisce solo il numero di destinatari
app.post('/api/admin/comunicazioni', verificaToken, soloDeveloper, async (req, res) => {
    const titolo = String(req.body.titolo ?? '').trim();
    const messaggio = String(req.body.messaggio ?? '').trim();
    const sedeId = req.body.sede_id == null || req.body.sede_id === '' ? null : Number(req.body.sede_id);
    const clienteUuid = req.body.cliente_uuid || null;
    if (!req.body.anteprima) {
        if (!titolo || titolo.length > 120) return res.status(400).json({ error: "Il titolo è obbligatorio (max 120 caratteri)" });
        if (!messaggio || messaggio.length > 2000) return res.status(400).json({ error: "Il messaggio è obbligatorio (max 2000 caratteri)" });
    }
    if (sedeId !== null && !Number.isInteger(sedeId)) return res.status(400).json({ error: "Sede non valida" });
    if (clienteUuid && !/^[0-9a-f-]{36}$/i.test(clienteUuid)) return res.status(400).json({ error: "Cliente non valido" });

    const client = await pool.connect();
    try {
        if (sedeId !== null && (await client.query('SELECT 1 FROM sedi WHERE id = $1', [sedeId])).rows.length === 0) {
            return res.status(400).json({ error: "Sede non valida" });
        }
        if (req.body.anteprima) {
            const n = (await client.query(DESTINATARI_SQL, [clienteUuid, sedeId])).rows.length;
            return res.json({ anteprima: true, destinatari: n, email: emailConfigurata() });
        }
        await client.query('BEGIN');
        const esito = await creaComunicazione(client, { titolo, messaggio, sedeId, clienteUuid, inviataDa: req.utente.uuid });
        if (esito.destinatari === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: "Nessun cliente destinatario" });
        }
        const aChi = clienteUuid ? '1 cliente' : sedeId
            ? `${esito.destinatari} clienti di ${(await client.query('SELECT nome FROM sedi WHERE id = $1', [sedeId])).rows[0].nome}`
            : `${esito.destinatari} clienti (tutti)`;
        await registraOperazione(client, req.utente, 'comunicazione', `Inviata comunicazione «${titolo}» a ${aChi}`,
            { comunicazione_id: esito.comunicazione.id, sede_id: sedeId, destinatari: esito.destinatari });
        await client.query('COMMIT');
        programmaEmail(esito.notifiche);
        res.json({
            success: true,
            comunicazione: esito.comunicazione,
            destinatari: esito.destinatari,
            email: emailConfigurata(),
            messaggio: `Comunicazione inviata a ${esitoInvio(esito.destinatari)}.`,
        });
    } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        console.error("Errore invio comunicazione:", err.message);
        res.status(500).json({ error: "Errore nell'invio della comunicazione" });
    } finally {
        client.release();
    }
});

// Storico delle comunicazioni inviate, con l'esito delle email
app.get('/api/admin/comunicazioni', verificaToken, soloDeveloper, async (req, res) => {
    try {
        const r = await pool.query(
            `SELECT c.id, c.titolo, c.messaggio, c.sede_id, c.destinatari, c.created_at,
                    count(n.email_inviata_at)::int AS email_inviate,
                    count(n.email_errore)::int AS email_fallite
             FROM comunicazioni c LEFT JOIN notifiche n ON n.comunicazione_id = c.id
             GROUP BY c.id ORDER BY c.created_at DESC LIMIT 50`
        );
        res.json(r.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// ==========================================
// APERTURE STRAORDINARIE (solo developer)
// ==========================================
// Elenco pubblico delle aperture da oggi in poi: serve al calendario dei clienti per rendere
// cliccabili solo quelle date (le altre domeniche e gli altri lunedì restano chiusi).
app.get('/api/aperture-straordinarie', async (req, res) => {
    const sedeId = req.query.sede_id ? Number(req.query.sede_id) : null;
    if (sedeId !== null && !Number.isInteger(sedeId)) return res.status(400).json({ error: "Sede non valida" });
    try {
        const r = await pool.query(
            `SELECT ${COLONNE_APERTURA} FROM aperture_straordinarie a JOIN sedi s ON s.id = a.sede_id
             WHERE a.data >= $1::date AND ($2::int IS NULL OR a.sede_id = $2::int)
             ORDER BY a.data, a.sede_id`,
            [oraItalia().data, sedeId]
        );
        res.json(r.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// Sblocca UNA data di chiusura per una sede. Con notifica_clienti: true avvisa tutti i clienti
// (in app e via email) contestualmente allo sblocco.
app.post('/api/admin/aperture-straordinarie', verificaToken, soloDeveloper, async (req, res) => {
    const { data, ora_inizio, ora_fine } = req.body;
    const sedeId = Number(req.body.sede_id);
    const barbieri = Array.isArray(req.body.barbieri) ? [...new Set(req.body.barbieri.map(Number))] : [];
    const oggi = oraItalia().data;
    if (!DATA_RE.test(data || '')) return res.status(400).json({ error: "Data non valida" });
    if (data < oggi) return res.status(400).json({ error: "La data è già passata" });
    if (!ORA_RE.test(ora_inizio || '') || !ORA_RE.test(ora_fine || '')) return res.status(400).json({ error: "Orario non valido" });
    if (minuti(ora_fine) - minuti(ora_inizio) < 40) return res.status(400).json({ error: "L'apertura deve durare almeno 40 minuti" });
    if (!Number.isInteger(sedeId)) return res.status(400).json({ error: "Sede non valida" });
    if (barbieri.length === 0 || barbieri.some((b) => !Number.isInteger(b))) return res.status(400).json({ error: "Seleziona almeno un barbiere" });

    const client = await pool.connect();
    try {
        const sede = (await client.query('SELECT nome FROM sedi WHERE id = $1', [sedeId])).rows[0];
        if (!sede) return res.status(400).json({ error: "Sede non valida" });
        // Solo un giorno di chiusura di QUESTA sede secondo l'orario standard
        if ((await fasceSede(client, sedeId, giornoDellaSettimana(data))).length > 0) {
            return res.status(400).json({ error: `In questo giorno ${sede.nome} è già aperta: l'apertura straordinaria serve solo per i giorni di chiusura` });
        }
        const esistenti = await client.query('SELECT count(*)::int AS n FROM barbieri WHERE id = ANY($1::int[])', [barbieri]);
        if (esistenti.rows[0].n !== barbieri.length) return res.status(400).json({ error: "Barbiere non valido" });

        await client.query('BEGIN');
        const ins = await client.query(
            `INSERT INTO aperture_straordinarie (data, sede_id, ora_inizio, ora_fine, barbieri, creata_da)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
            [data, sedeId, ora_inizio, ora_fine, barbieri, req.utente.uuid]
        );
        const id = ins.rows[0].id;
        let avviso = { destinatari: 0, notifiche: [] };
        if (req.body.notifica_clienti) {
            avviso = await creaComunicazione(client, {
                titolo: `Apertura straordinaria — ${fmtData(data)}`,
                messaggio: `La sede di **${sede.nome}** sarà aperta in via straordinaria **${fmtData(data)}** dalle **${ora_inizio}** alle **${ora_fine}**.\n\nPrenota subito il tuo appuntamento dall'app: i posti sono limitati!`,
                inviataDa: req.utente.uuid,
            });
            if (avviso.comunicazione) {
                await client.query('UPDATE aperture_straordinarie SET comunicazione_id = $2 WHERE id = $1', [id, avviso.comunicazione.id]);
            }
        }
        await registraOperazione(client, req.utente, 'apertura_straordinaria',
            `Sbloccata data ${fmtData(data)} ${data.slice(0, 4)} a ${sede.nome}, ${ora_inizio}–${ora_fine}`
            + (req.body.notifica_clienti ? ` (avviso a ${avviso.destinatari} clienti)` : ''),
            { apertura_id: id, data, sede_id: sedeId, ora_inizio, ora_fine, barbieri, destinatari: avviso.destinatari });
        await client.query('COMMIT');
        programmaEmail(avviso.notifiche);
        const apertura = (await pool.query(`SELECT ${COLONNE_APERTURA} FROM aperture_straordinarie a JOIN sedi s ON s.id = a.sede_id WHERE a.id = $1`, [id])).rows[0];
        res.json({
            success: true,
            apertura,
            destinatari: avviso.destinatari,
            messaggio: `${fmtData(data)} sbloccato a ${sede.nome} dalle ${ora_inizio} alle ${ora_fine}.`
                + (req.body.notifica_clienti ? ` Avviso inviato a ${esitoInvio(avviso.destinatari)}.` : ''),
        });
    } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        if (err.code === '23505') return res.status(409).json({ error: "Questa data è già sbloccata per questa sede" });
        console.error("Errore apertura straordinaria:", err.message);
        res.status(500).json({ error: "Errore nel salvataggio dell'apertura straordinaria" });
    } finally {
        client.release();
    }
});

// Annulla un'apertura straordinaria: gli appuntamenti già presi quel giorno in quella sede vengono
// cancellati e i clienti avvisati (in app e via email), come per le assenze.
app.delete('/api/admin/aperture-straordinarie/:id', verificaToken, soloDeveloper, async (req, res) => {
    if (!/^\d+$/.test(req.params.id)) return res.status(404).json({ error: "Non trovata" });
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const r = await client.query(
            `SELECT a.id, a.data::text AS data, a.sede_id, s.nome AS sede_nome
             FROM aperture_straordinarie a JOIN sedi s ON s.id = a.sede_id WHERE a.id = $1 FOR UPDATE OF a`,
            [req.params.id]
        );
        if (r.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: "Non trovata" });
        }
        const a = r.rows[0];
        const app_ = await client.query(
            `SELECT p.id, p.cliente_uuid, p.data, p.ora, b.nome AS barbiere_nome, sv.nome AS servizio_nome
             FROM prenotazioni p
             JOIN barbieri b ON b.id = p.barbiere_id
             JOIN servizi sv ON sv.id = p.servizio_id
             WHERE p.data = $1::date AND p.sede_id = $2 AND p.stato = 'attivo'`,
            [a.data, a.sede_id]
        );
        const notifiche = [];
        for (const p of app_.rows) {
            await client.query("UPDATE prenotazioni SET stato = 'cancellato' WHERE id = $1", [p.id]);
            if (p.cliente_uuid) {
                const messaggio = `Ci scusiamo per il disagio. Il tuo appuntamento di **${fmtData(p.data)}** alle **${String(p.ora).slice(0, 5)}** con **${p.barbiere_nome}** per il servizio di **${p.servizio_nome}** è stato cancellato perché l'apertura straordinaria di quel giorno è stata annullata.\n\nTi invitiamo a prenotare un nuovo appuntamento.`;
                notifiche.push(await creaNotifica(client, { cliente_uuid: p.cliente_uuid, tipo: 'cancellazione', titolo: 'Appuntamento cancellato', messaggio }));
            }
        }
        await client.query('DELETE FROM aperture_straordinarie WHERE id = $1', [a.id]);
        await registraOperazione(client, req.utente, 'apertura_annullata',
            `Annullata apertura straordinaria di ${fmtData(a.data)} ${a.data.slice(0, 4)} a ${a.sede_nome}`
            + (app_.rows.length > 0 ? ` (${app_.rows.length} appuntamenti cancellati)` : ''),
            { data: a.data, sede_id: a.sede_id, appuntamenti_cancellati: app_.rows.length });
        await client.query('COMMIT');
        programmaEmail(notifiche);
        res.json({
            success: true,
            cancellati: app_.rows.length,
            messaggio: `Apertura straordinaria di ${fmtData(a.data)} annullata.`
                + (app_.rows.length > 0 ? ` ${app_.rows.length} appuntamenti cancellati e clienti avvisati.` : ''),
        });
    } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        console.error("Errore annullamento apertura:", err.message);
        res.status(500).json({ error: "Errore" });
    } finally {
        client.release();
    }
});

// ==========================================
// CONSOLE DEVELOPER: ORARI SEDI, TURNI BARBIERI, ARCHIVIO OPERAZIONI
// ==========================================
const GIORNI_BREVI = ['Dom', 'Lun', 'Mar', 'Mer', 'Gio', 'Ven', 'Sab'];
const ORDINE_SETTIMANA = [1, 2, 3, 4, 5, 6, 0]; // da lunedì a domenica, per le descrizioni

// Orario settimanale di una o tutte le sedi: [{ sede_id, giorno_settimana, fasce: [{ inizio, fine }] }]
// per tutti i 7 giorni (fasce vuote = chiuso). Pubblico: serve al calendario cliente e a "Le nostre sedi".
const orariSettimanali = async (db, sedeId = null) => {
    const sedi = (await db.query('SELECT id FROM sedi WHERE ($1::int IS NULL OR id = $1::int) ORDER BY id', [sedeId])).rows;
    const r = await db.query(
        `SELECT sede_id, giorno_settimana, to_char(ora_inizio, 'HH24:MI') AS inizio, to_char(ora_fine, 'HH24:MI') AS fine
         FROM orari_sedi WHERE ($1::int IS NULL OR sede_id = $1::int) ORDER BY sede_id, giorno_settimana, ora_inizio`,
        [sedeId]
    );
    return sedi.flatMap((s) => [0, 1, 2, 3, 4, 5, 6].map((g) => ({
        sede_id: s.id,
        giorno_settimana: g,
        fasce: r.rows.filter((x) => x.sede_id === s.id && x.giorno_settimana === g).map(({ inizio, fine }) => ({ inizio, fine })),
    })));
};

app.get('/api/orari-sedi', async (req, res) => {
    const sedeId = req.query.sede_id ? Number(req.query.sede_id) : null;
    if (sedeId !== null && !Number.isInteger(sedeId)) return res.status(400).json({ error: "Sede non valida" });
    try {
        res.json(await orariSettimanali(pool, sedeId));
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// Sostituisce l'orario settimanale di una sede. Body: { giorni: { "0": [], "2": [{ inizio, fine }, …], … } }
// (un giorno assente o con [] = chiuso). Gli appuntamenti già presi non vengono toccati: la risposta
// segnala quanti, da oggi in poi, cadono fuori dal nuovo orario.
app.put('/api/admin/orari-sedi/:sede_id', verificaToken, soloDeveloper, async (req, res) => {
    const sedeId = Number(req.params.sede_id);
    const giorni = req.body?.giorni;
    if (!Number.isInteger(sedeId)) return res.status(400).json({ error: "Sede non valida" });
    if (!giorni || typeof giorni !== 'object') return res.status(400).json({ error: "Orario mancante" });
    const nuovo = {};
    for (let g = 0; g <= 6; g++) {
        const fasce = Array.isArray(giorni[g]) ? giorni[g] : [];
        if (fasce.length > 3) return res.status(400).json({ error: `${GIORNI[g]}: al massimo 3 fasce` });
        const ordinate = [...fasce].sort((a, b) => String(a?.inizio).localeCompare(String(b?.inizio)));
        for (let i = 0; i < ordinate.length; i++) {
            const { inizio, fine } = ordinate[i] || {};
            if (!ORA_RE.test(inizio || '') || !ORA_RE.test(fine || '')) return res.status(400).json({ error: `${GIORNI[g]}: orario non valido` });
            if (minuti(fine) - minuti(inizio) < 20) return res.status(400).json({ error: `${GIORNI[g]}: ogni fascia deve durare almeno 20 minuti` });
            if (i > 0 && minuti(inizio) < minuti(ordinate[i - 1].fine)) return res.status(400).json({ error: `${GIORNI[g]}: le fasce si sovrappongono` });
        }
        nuovo[g] = ordinate.map(({ inizio, fine }) => ({ inizio, fine }));
    }
    const client = await pool.connect();
    try {
        const sede = (await client.query('SELECT nome FROM sedi WHERE id = $1', [sedeId])).rows[0];
        if (!sede) return res.status(400).json({ error: "Sede non valida" });
        await client.query('BEGIN');
        await client.query('DELETE FROM orari_sedi WHERE sede_id = $1', [sedeId]);
        for (let g = 0; g <= 6; g++) {
            for (const f of nuovo[g]) {
                await client.query('INSERT INTO orari_sedi (sede_id, giorno_settimana, ora_inizio, ora_fine) VALUES ($1, $2, $3, $4)', [sedeId, g, f.inizio, f.fine]);
            }
        }
        // Appuntamenti futuri della sede che non stanno più in una fascia (esclusi i giorni di apertura straordinaria)
        const futuri = await client.query(
            `SELECT p.data::text AS data, to_char(p.ora, 'HH24:MI') AS ora, COALESCE(sv.durata_minuti, 40) AS durata
             FROM prenotazioni p LEFT JOIN servizi sv ON sv.id = p.servizio_id
             WHERE p.sede_id = $1 AND p.stato = 'attivo' AND p.data >= $2::date
               AND NOT EXISTS (SELECT 1 FROM aperture_straordinarie a WHERE a.data = p.data AND a.sede_id = p.sede_id)`,
            [sedeId, oraItalia().data]
        );
        const fuoriOrario = futuri.rows.filter((p) => !nuovo[giornoDellaSettimana(p.data)].some((f) =>
            minuti(p.ora) >= minuti(f.inizio) && minuti(p.ora) + p.durata <= minuti(f.fine))).length;
        const riepilogo = ORDINE_SETTIMANA.map((g) => `${GIORNI_BREVI[g]} ${nuovo[g].length ? nuovo[g].map((f) => `${f.inizio}–${f.fine}`).join(', ') : 'chiuso'}`).join(' · ');
        await registraOperazione(client, req.utente, 'orari_sede', `Modificato orario ${sede.nome}: ${riepilogo}`, { sede_id: sedeId, giorni: nuovo });
        await client.query('COMMIT');
        res.json({
            success: true,
            orari: await orariSettimanali(pool, sedeId),
            fuori_orario: fuoriOrario,
            messaggio: `Orario di ${sede.nome} aggiornato.`
                + (fuoriOrario > 0 ? ` Attenzione: ${fuoriOrario} appuntamenti già presi cadono fuori dal nuovo orario (restano validi).` : ''),
        });
    } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        console.error("Errore orari sede:", err.message);
        res.status(500).json({ error: "Errore nel salvataggio dell'orario" });
    } finally {
        client.release();
    }
});

// Turni fissi di tutti i barbieri: [{ id, nome, turni: { "2": sede_id, … } }] (giorno assente = riposo)
const turniBarbieri = async (db) => {
    const b = await db.query('SELECT id, nome FROM barbieri ORDER BY id');
    const t = await db.query('SELECT barbiere_id, giorno_settimana, sede_id FROM turni_rotazione');
    return b.rows.map((x) => ({
        ...x,
        turni: Object.fromEntries(t.rows.filter((r) => r.barbiere_id === x.id).map((r) => [r.giorno_settimana, r.sede_id])),
    }));
};

app.get('/api/admin/turni', verificaToken, soloDeveloper, async (req, res) => {
    try {
        res.json(await turniBarbieri(pool));
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// Sostituisce i turni fissi di un barbiere. Body: { turni: { "2": 1, "3": 2, … } } (una sede per giorno).
// Gli appuntamenti già presi non vengono toccati: la risposta segnala quanti cadono in giorni non più di turno.
app.put('/api/admin/turni/:barbiere_id', verificaToken, soloDeveloper, async (req, res) => {
    const barbiereId = Number(req.params.barbiere_id);
    const turni = req.body?.turni;
    if (!Number.isInteger(barbiereId)) return res.status(400).json({ error: "Barbiere non valido" });
    if (!turni || typeof turni !== 'object') return res.status(400).json({ error: "Turni mancanti" });
    const nuovi = [];
    for (const [g, s] of Object.entries(turni)) {
        if (s == null || s === '') continue;
        if (!/^[0-6]$/.test(g) || !Number.isInteger(Number(s))) return res.status(400).json({ error: "Turno non valido" });
        nuovi.push([Number(g), Number(s)]);
    }
    const client = await pool.connect();
    try {
        const barbiere = (await client.query('SELECT nome FROM barbieri WHERE id = $1', [barbiereId])).rows[0];
        if (!barbiere) return res.status(404).json({ error: "Barbiere non trovato" });
        const sedi = new Map((await client.query('SELECT id, nome FROM sedi')).rows.map((s) => [s.id, s.nome]));
        if (nuovi.some(([, s]) => !sedi.has(s))) return res.status(400).json({ error: "Sede non valida" });
        await client.query('BEGIN');
        await client.query('DELETE FROM turni_rotazione WHERE barbiere_id = $1', [barbiereId]);
        for (const [g, s] of nuovi) {
            await client.query('INSERT INTO turni_rotazione (barbiere_id, sede_id, giorno_settimana) VALUES ($1, $2, $3)', [barbiereId, s, g]);
        }
        // fisso = una sola sede, rotante = più sedi nella settimana
        await client.query('UPDATE barbieri SET tipo = $2 WHERE id = $1', [barbiereId, new Set(nuovi.map(([, s]) => s)).size > 1 ? 'rotante' : 'fisso']);
        // Appuntamenti futuri del barbiere in un giorno/sede non più di turno (esclusi quelli in aperture straordinarie)
        const futuri = await client.query(
            `SELECT p.data::text AS data, p.sede_id FROM prenotazioni p
             WHERE p.barbiere_id = $1 AND p.stato = 'attivo' AND p.data >= $2::date
               AND NOT EXISTS (SELECT 1 FROM aperture_straordinarie a WHERE a.data = p.data AND a.sede_id = p.sede_id AND $1 = ANY(a.barbieri))`,
            [barbiereId, oraItalia().data]
        );
        const mappa = new Map(nuovi);
        const fuoriTurno = futuri.rows.filter((p) => mappa.get(giornoDellaSettimana(p.data)) !== p.sede_id).length;
        const riepilogo = ORDINE_SETTIMANA.filter((g) => mappa.has(g)).map((g) => `${GIORNI_BREVI[g]} ${sedi.get(mappa.get(g))}`).join(', ') || 'nessun giorno di turno';
        await registraOperazione(client, req.utente, 'turni_barbiere', `Modificati turni di ${barbiere.nome}: ${riepilogo}`, { barbiere_id: barbiereId, turni: Object.fromEntries(nuovi) });
        await client.query('COMMIT');
        res.json({
            success: true,
            fuori_turno: fuoriTurno,
            messaggio: `Turni di ${barbiere.nome} aggiornati.`
                + (fuoriTurno > 0 ? ` Attenzione: ${fuoriTurno} appuntamenti già presi cadono in giorni non più di turno (restano validi).` : ''),
        });
    } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        console.error("Errore turni:", err.message);
        res.status(500).json({ error: "Errore nel salvataggio dei turni" });
    } finally {
        client.release();
    }
});

// Archivio operazioni filtrato per mese/anno (ora italiana)
const ETICHETTA_AZIONE = {
    comunicazione: 'Comunicazione inviata',
    apertura_straordinaria: 'Apertura straordinaria',
    apertura_annullata: 'Apertura annullata',
    orari_sede: 'Orario sede modificato',
    turni_barbiere: 'Turni barbiere modificati',
};
const leggiOperazioni = async (anno, mese) => {
    const r = await pool.query(
        `SELECT id, azione, descrizione,
                to_char(created_at AT TIME ZONE 'Europe/Rome', 'YYYY-MM-DD') AS data,
                to_char(created_at AT TIME ZONE 'Europe/Rome', 'HH24:MI') AS ora
         FROM developer_logs
         WHERE (created_at AT TIME ZONE 'Europe/Rome') >= make_date($1, $2, 1)
           AND (created_at AT TIME ZONE 'Europe/Rome') < make_date($1, $2, 1) + interval '1 month'
         ORDER BY created_at DESC`,
        [anno, mese]
    );
    return r.rows.map((x) => ({ ...x, azione_etichetta: ETICHETTA_AZIONE[x.azione] || x.azione }));
};
const meseValido = (q) => {
    const anno = Number(q.anno), mese = Number(q.mese);
    return Number.isInteger(anno) && anno >= 2020 && anno <= 2100 && Number.isInteger(mese) && mese >= 1 && mese <= 12 ? { anno, mese } : null;
};

app.get('/api/admin/developer-logs', verificaToken, soloDeveloper, async (req, res) => {
    const p = meseValido(req.query);
    if (!p) return res.status(400).json({ error: "Mese o anno non validi" });
    try {
        res.json(await leggiOperazioni(p.anno, p.mese));
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// Report CSV del mese (separatore ";" e BOM UTF-8: si apre direttamente in Excel con accenti corretti)
app.get('/api/admin/developer-logs/export', verificaToken, soloDeveloper, async (req, res) => {
    const p = meseValido(req.query);
    if (!p) return res.status(400).json({ error: "Mese o anno non validi" });
    try {
        const righe = (await leggiOperazioni(p.anno, p.mese)).reverse(); // in ordine cronologico
        const cella = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
        const csv = [
            ['Data', 'Ora', 'Tipo di azione', 'Descrizione'].map(cella).join(';'),
            ...righe.map((x) => [x.data.split('-').reverse().join('/'), x.ora, x.azione_etichetta, x.descrizione].map(cella).join(';')),
        ].join('\r\n');
        const nome = `report-operazioni-${p.anno}-${String(p.mese).padStart(2, '0')}.csv`;
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="${nome}"`);
        res.send('﻿' + csv + '\r\n');
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});
