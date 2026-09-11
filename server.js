const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config();
const cron = require('node-cron');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

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

// ==========================================
// CRON JOB - Pulizia ogni 10 minuti
// ==========================================
cron.schedule('*/10 * * * *', async () => {
    try {
        const cancellati = await pool.query("DELETE FROM prenotazioni WHERE stato = 'cancellato' AND data < CURRENT_DATE");
        const passati = await pool.query("DELETE FROM prenotazioni WHERE data < CURRENT_DATE AND stato = 'attivo'");
        const totale = (cancellati.rowCount || 0) + (passati.rowCount || 0);
        if (totale > 0) console.log(`Pulizia: eliminati ${totale} appuntamenti`);

        // Ora italiana corrente come stringa locale (YYYY-MM-DDTHH:MM:SS) — evita problemi UTC
        const italianNow = new Date().toLocaleString('sv-SE', { timeZone: 'Europe/Rome' }).replace(' ', 'T');

        // Riattiva barbieri con assenza/permesso scaduto (formato JSON)
        const attiviBarbieri = await pool.query(
            `SELECT id, motivo_assenza FROM barbieri WHERE assente = true AND motivo_assenza IS NOT NULL`
        );
        for (const b of attiviBarbieri.rows) {
            try {
                if (b.motivo_assenza.startsWith('{')) {
                    const info = JSON.parse(b.motivo_assenza);
                    if (info.tipo === 'permesso' && info.fine <= italianNow) {
                        await pool.query('UPDATE barbieri SET assente = false, motivo_assenza = NULL WHERE id = $1', [b.id]);
                        console.log(`Permesso scaduto: riattivato barbiere ${b.id}`);
                    } else if (info.tipo === 'assente' && info.fine) {
                        if ((info.fine + 'T23:59:59') < italianNow) {
                            await pool.query('UPDATE barbieri SET assente = false, motivo_assenza = NULL WHERE id = $1', [b.id]);
                            console.log(`Assenza scaduta: riattivato barbiere ${b.id}`);
                        }
                    }
                } else if (b.motivo_assenza.startsWith('permesso:')) {
                    // Retrocompatibilità formato vecchio
                    if (new Date(b.motivo_assenza.substring(9)) < new Date()) {
                        await pool.query('UPDATE barbieri SET assente = false, motivo_assenza = NULL WHERE id = $1', [b.id]);
                        console.log(`Permesso (legacy) scaduto: riattivato barbiere ${b.id}`);
                    }
                }
            } catch (e) { /* skip barbieri con motivo_assenza non parsabile */ }
        }

        // Attiva assenze/permessi programmati il cui inizio è arrivato
        const programmati = await pool.query(
            `SELECT id, motivo_assenza FROM barbieri WHERE assente = false AND motivo_assenza IS NOT NULL AND motivo_assenza LIKE '{%'`
        );
        for (const b of programmati.rows) {
            try {
                const info = JSON.parse(b.motivo_assenza);
                if (info.stato !== 'programmato') continue;
                const inizioStr = info.tipo === 'assente'
                    ? info.inizio + 'T00:00:00'
                    : info.inizio;
                if (inizioStr <= italianNow) {
                    info.stato = 'attivo';
                    await pool.query('UPDATE barbieri SET assente = true, motivo_assenza = $1 WHERE id = $2',
                        [JSON.stringify(info), b.id]);
                    if (info.tipo === 'assente') {
                        const params = [b.id];
                        let cancelQuery = `SELECT p.id, p.cliente_uuid, p.data, p.ora, bv.nome AS barbiere_nome, sv.nome AS servizio_nome
                            FROM prenotazioni p
                            JOIN barbieri bv ON p.barbiere_id = bv.id
                            JOIN servizi sv ON p.servizio_id = sv.id
                            WHERE p.barbiere_id = $1 AND p.stato = 'attivo'
                            AND (p.data > CURRENT_DATE OR (p.data = CURRENT_DATE AND p.ora > CURRENT_TIME))`;
                        if (info.fine) { cancelQuery += ` AND p.data <= $2`; params.push(info.fine); }
                        const apps = await pool.query(cancelQuery, params);
                        for (const app of apps.rows) {
                            if (app.cliente_uuid) {
                                const dateObj = new Date(app.data);
                                const giorni = ['Dom','Lun','Mar','Mer','Gio','Ven','Sab'];
                                const mesi = ['Gennaio','Febbraio','Marzo','Aprile','Maggio','Giugno','Luglio','Agosto','Settembre','Ottobre','Novembre','Dicembre'];
                                const dataFmt = `${giorni[dateObj.getDay()]} ${dateObj.getDate()} ${mesi[dateObj.getMonth()]}`;
                                const messaggio = `Ci scusiamo per il disagio. Il tuo appuntamento di **${dataFmt}** alle **${app.ora.slice(0,5)}** con **${app.barbiere_nome}** per il servizio di **${app.servizio_nome}** è stato cancellato perché il barbiere non è disponibile.\n\nTi invitiamo a prenotare un nuovo appuntamento.`;
                                await pool.query('INSERT INTO notifiche (cliente_uuid, messaggio) VALUES ($1, $2)', [app.cliente_uuid, messaggio]);
                            }
                        }
                        // Notifica clienti prima di marcare cancellato
                        const appAssParams = [b.id];
                        let appAssQuery = `SELECT p.id, p.cliente_uuid, p.data, p.ora, bv.nome AS barbiere_nome, sv.nome AS servizio_nome
                            FROM prenotazioni p
                            JOIN barbieri bv ON p.barbiere_id = bv.id
                            JOIN servizi sv ON p.servizio_id = sv.id
                            WHERE p.barbiere_id = $1 AND p.stato = 'attivo'
                            AND (p.data > CURRENT_DATE OR (p.data = CURRENT_DATE AND p.ora > CURRENT_TIME))`;
                        if (info.fine) { appAssQuery += ` AND p.data <= $2`; appAssParams.push(info.fine); }
                        const appAssRows = await pool.query(appAssQuery, appAssParams);
                        for (const app of appAssRows.rows) {
                            if (app.cliente_uuid) {
                                const dateObj = new Date(app.data + 'T12:00:00');
                                const giorni = ['Dom','Lun','Mar','Mer','Gio','Ven','Sab'];
                                const mesi = ['Gennaio','Febbraio','Marzo','Aprile','Maggio','Giugno','Luglio','Agosto','Settembre','Ottobre','Novembre','Dicembre'];
                                const dataFmt = `${giorni[dateObj.getDay()]} ${dateObj.getDate()} ${mesi[dateObj.getMonth()]}`;
                                const msg = `Ci scusiamo per il disagio. Il tuo appuntamento di **${dataFmt}** alle **${app.ora.slice(0,5)}** con **${app.barbiere_nome}** per il servizio di **${app.servizio_nome}** è stato cancellato perché il barbiere non è disponibile.\n\nTi invitiamo a prenotare un nuovo appuntamento.`;
                                await pool.query('INSERT INTO notifiche (cliente_uuid, messaggio) VALUES ($1, $2)', [app.cliente_uuid, msg]);
                            }
                        }
                        // Marca cancellato (non elimina) — così è ripristinabile alla riattivazione
                        const delParams = [b.id];
                        let delQuery = `UPDATE prenotazioni SET stato = 'cancellato'
                            WHERE barbiere_id = $1 AND stato = 'attivo'
                            AND (data > CURRENT_DATE OR (data = CURRENT_DATE AND ora > CURRENT_TIME))`;
                        if (info.fine) { delQuery += ` AND data <= $2`; delParams.push(info.fine); }
                        const eliminati = await pool.query(delQuery, delParams);
                        console.log(`Assenza programmata attivata per barbiere ${b.id}: cancellati ${eliminati.rowCount} appuntamenti`);
                    } else {
                        // Permesso: cancella appuntamenti nella finestra e notifica i clienti
                        const oraInizioP = info.inizio.slice(11, 16);
                        const oraFineP = info.fine.slice(11, 16);
                        const dataP = info.inizio.slice(0, 10);
                        const appsP = await pool.query(
                            `SELECT p.id, p.cliente_uuid, p.data, p.ora, bv.nome AS barbiere_nome, sv.nome AS servizio_nome
                             FROM prenotazioni p
                             JOIN barbieri bv ON p.barbiere_id = bv.id
                             JOIN servizi sv ON p.servizio_id = sv.id
                             WHERE p.barbiere_id = $1 AND p.data = $2 AND p.stato = 'attivo'
                             AND p.ora >= $3 AND p.ora < $4`,
                            [b.id, dataP, oraInizioP, oraFineP]
                        );
                        for (const app of appsP.rows) {
                            if (app.cliente_uuid) {
                                const dateObj = new Date(app.data + 'T12:00:00');
                                const giorni = ['Dom','Lun','Mar','Mer','Gio','Ven','Sab'];
                                const mesi = ['Gennaio','Febbraio','Marzo','Aprile','Maggio','Giugno','Luglio','Agosto','Settembre','Ottobre','Novembre','Dicembre'];
                                const dataFmt = `${giorni[dateObj.getDay()]} ${dateObj.getDate()} ${mesi[dateObj.getMonth()]}`;
                                const msg = `Ci scusiamo per il disagio. Il tuo appuntamento di **${dataFmt}** alle **${app.ora.slice(0,5)}** con **${app.barbiere_nome}** per il servizio di **${app.servizio_nome}** è stato cancellato perché il barbiere è in permesso.\n\nTi invitiamo a prenotare un nuovo appuntamento.`;
                                await pool.query('INSERT INTO notifiche (cliente_uuid, messaggio) VALUES ($1, $2)', [app.cliente_uuid, msg]);
                            }
                        }
                        await pool.query(
                            `UPDATE prenotazioni SET stato = 'cancellato'
                             WHERE barbiere_id = $1 AND data = $2 AND stato = 'attivo'
                             AND ora >= $3 AND ora < $4`,
                            [b.id, dataP, oraInizioP, oraFineP]
                        );
                        console.log(`Permesso programmato attivato per barbiere ${b.id}: cancellati ${appsP.rowCount} appuntamenti`);
                    }
                }
            } catch (e) { console.error('Errore attivazione programmato:', e); }
        }
    } catch (err) {
        console.error('Errore pulizia:', err);
    }
});

// ==========================================
// AUTH: REGISTRAZIONE + LOGIN UNIFICATO
// ==========================================

// Registrazione cliente
app.post('/api/auth/registrazione', async (req, res) => {
    const { nome, cognome, email, telefono, password } = req.body;

    if (!nome || !email || !password) {
        return res.status(400).json({ error: "Nome, email e password sono obbligatori" });
    }

    try {
        // Controlla che l'email non esista già tra clienti
        const esistente = await pool.query('SELECT id FROM clienti WHERE email = $1', [email]);
        if (esistente.rows.length > 0) {
            return res.status(409).json({ error: "Questa email è già registrata" });
        }

        // Controlla che non sia un'email barbiere
        const barbiere = await pool.query('SELECT id FROM barbieri WHERE email = $1', [email]);
        if (barbiere.rows.length > 0) {
            return res.status(409).json({ error: "Questa email è riservata" });
        }

        const hash = await bcrypt.hash(password, 10);
        const result = await pool.query(
            `INSERT INTO clienti (nome, cognome, email, telefono, password_hash) VALUES ($1, $2, $3, $4, $5) RETURNING id, nome, cognome, email`,
            [nome, cognome || null, email, telefono || null, hash]
        );

        const cliente = result.rows[0];
        const token = jwt.sign(
            { id: cliente.id, nome: cliente.nome, email: cliente.email, ruolo: 'cliente' },
            process.env.JWT_SECRET, { expiresIn: '30d' }
        );

        res.json({ success: true, token, utente: { ...cliente, ruolo: 'cliente' } });
    } catch (err) {
        console.error("Errore registrazione:", err);
        res.status(500).json({ error: "Errore durante la registrazione" });
    }
});

// Login unificato (clienti + barbieri)
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Inserisci email e password" });

    try {
        // 1. Cerca tra i barbieri
        const barbiereResult = await pool.query('SELECT * FROM barbieri WHERE email = $1', [email]);
        if (barbiereResult.rows.length > 0) {
            const barbiere = barbiereResult.rows[0];
            if (!barbiere.password_hash) return res.status(401).json({ error: "Password non configurata" });

            const valida = await bcrypt.compare(password, barbiere.password_hash);
            if (!valida) return res.status(401).json({ error: "Password errata" });

            const token = jwt.sign(
                { id: barbiere.id, nome: barbiere.nome, email: barbiere.email, tipo: barbiere.tipo, ruolo: 'barbiere' },
                process.env.JWT_SECRET, { expiresIn: '30d' }
            );
            return res.json({ success: true, token, utente: { id: barbiere.id, nome: barbiere.nome, ruolo: 'barbiere', tipo: barbiere.tipo } });
        }

        // 2. Cerca tra i clienti
        const clienteResult = await pool.query('SELECT * FROM clienti WHERE email = $1', [email]);
        if (clienteResult.rows.length > 0) {
            const cliente = clienteResult.rows[0];
            if (!cliente.password_hash) return res.status(401).json({ error: "Password non configurata" });

            const valida = await bcrypt.compare(password, cliente.password_hash);
            if (!valida) return res.status(401).json({ error: "Password errata" });

            const token = jwt.sign(
                { id: cliente.id, nome: cliente.nome, email: cliente.email, ruolo: 'cliente' },
                process.env.JWT_SECRET, { expiresIn: '30d' }
            );
            return res.json({ success: true, token, utente: { id: cliente.id, nome: cliente.nome, cognome: cliente.cognome, ruolo: 'cliente' } });
        }

        return res.status(401).json({ error: "Email non trovata" });
    } catch (err) {
        console.error("Errore login:", err);
        res.status(500).json({ error: "Errore durante il login" });
    }
});

// Verifica token (per auto-login)
app.get('/api/auth/me', verificaToken, async (req, res) => {
    try {
        if (req.utente.ruolo === 'barbiere') {
            const sedi = await pool.query(
                `SELECT DISTINCT s.id, s.nome FROM sedi s JOIN turni_rotazione t ON s.id = t.sede_id WHERE t.barbiere_id = $1 ORDER BY s.id`,
                [req.utente.id]
            );
            return res.json({ utente: req.utente, sedi: sedi.rows });
        }
        res.json({ utente: req.utente });
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// Setup password barbieri (chiamare UNA VOLTA)
app.get('/api/admin/setup-passwords', async (req, res) => {
    try {
        const barbieri = await pool.query('SELECT id, nome FROM barbieri');
        for (const b of barbieri.rows) {
            const hash = await bcrypt.hash('barberia2024', 10);
            await pool.query('UPDATE barbieri SET password_hash = $1 WHERE id = $2', [hash, b.id]);
        }
        res.json({ success: true, message: "Password impostate per tutti (password: barberia2024)" });
    } catch (err) {
        console.error("IL VERO ERRORE È:", err);
        res.status(500).json({ error: "Errore setup" });
    }
});

// Modifica profilo cliente
app.patch('/api/auth/profilo', verificaToken, async (req, res) => {
    const { nome, cognome, telefono } = req.body;
    try {
        if (req.utente.ruolo === 'cliente') {
            await pool.query('UPDATE profili SET nome=$1, cognome=$2, telefono=$3 WHERE id=$4', [nome, cognome, telefono, req.utente.id]);
            // Aggiorna anche il nome nelle prenotazioni future
            await pool.query("UPDATE prenotazioni SET cliente_nome=$1 WHERE cliente_id=$2 AND stato='attivo'", [nome, req.utente.id]);
        } else {
            await pool.query('UPDATE barbieri SET nome=$1 WHERE id=$2', [nome, req.utente.id]);
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Errore aggiornamento profilo" });
    }
});

// Cambia password
app.patch('/api/auth/cambia-password', verificaToken, async (req, res) => {
    const { vecchia_password, nuova_password } = req.body;
    if (!vecchia_password || !nuova_password) return res.status(400).json({ error: "Compila tutti i campi" });
    if (nuova_password.length < 6) return res.status(400).json({ error: "Minimo 6 caratteri" });

    try {
        let result;
        if (req.utente.ruolo === 'cliente') {
            result = await pool.query('SELECT password_hash FROM clienti WHERE id=$1', [req.utente.id]);
        } else {
            result = await pool.query('SELECT password_hash FROM barbieri WHERE id=$1', [req.utente.id]);
        }
        if (result.rows.length === 0) return res.status(404).json({ error: "Utente non trovato" });

        const valida = await bcrypt.compare(vecchia_password, result.rows[0].password_hash);
        if (!valida) return res.status(401).json({ error: "Password attuale errata" });

        const hash = await bcrypt.hash(nuova_password, 10);
        if (req.utente.ruolo === 'cliente') {
            await pool.query('UPDATE clienti SET password_hash=$1 WHERE id=$2', [hash, req.utente.id]);
        } else {
            await pool.query('UPDATE barbieri SET password_hash=$1 WHERE id=$2', [hash, req.utente.id]);
        }
        res.json({ success: true });
    } catch (err) {
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
             WHERE t.sede_id = $1 AND b.assente = false`,
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
            `SELECT b.id, b.nome, b.assente, b.motivo_assenza FROM barbieri b
             JOIN turni_rotazione t ON b.id = t.barbiere_id
             WHERE t.sede_id = $1 AND t.giorno_settimana = $2`,
            [sede_id, giorno_settimana]
        );
        // Calcola se un barbiere è disabilitato per la data richiesta (assente attivo o programmato)
        const rows = result.rows.map((b) => {
            let disabilitato = false;
            if (b.assente) {
                disabilitato = true;
            } else if (b.motivo_assenza && b.motivo_assenza.startsWith('{')) {
                try {
                    const info = JSON.parse(b.motivo_assenza);
                    if (info.stato === 'programmato') {
                        if (info.tipo === 'assente') {
                            disabilitato = data >= info.inizio && (!info.fine || data <= info.fine);
                        } else if (info.tipo === 'permesso') {
                            // Per il permesso programmato controlliamo solo la data (non l'ora)
                            const permDate = new Date(info.inizio);
                            const permDateStr = `${permDate.getFullYear()}-${String(permDate.getMonth()+1).padStart(2,'0')}-${String(permDate.getDate()).padStart(2,'0')}`;
                            disabilitato = permDateStr === data;
                        }
                    }
                } catch {}
            }
            return { id: b.id, nome: b.nome, assente: b.assente, disabilitato };
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
        let query = `
            SELECT p.id, p.data, p.ora, p.stato, p.sede_id,
                    s.nome AS sede_nome, b.nome AS barbiere_nome,
                    sv.nome AS servizio_nome, sv.prezzo AS servizio_prezzo
             FROM prenotazioni p
             JOIN sedi s ON p.sede_id = s.id
             JOIN barbieri b ON p.barbiere_id = b.id
             JOIN servizi sv ON p.servizio_id = sv.id
             WHERE p.cliente_uuid = $1 AND p.stato = 'attivo'
             AND (p.data > CURRENT_DATE OR (p.data = CURRENT_DATE AND p.ora >= CURRENT_TIME))`;
        const params = [cliente_uuid];

        if (sede_id) { query += ` AND p.sede_id = $2`; params.push(sede_id); }
        query += ` ORDER BY p.data ASC, p.ora ASC`;

        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore nel recupero delle prenotazioni" });
    }
});

// Cancella prenotazione (cliente)
app.delete('/api/prenotazioni/:id', verificaToken, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query(
            "DELETE FROM prenotazioni WHERE id = $1 AND stato = 'attivo' RETURNING *", [id]
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
        const result = await pool.query("DELETE FROM prenotazioni WHERE id = $1 RETURNING *", [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: "Non trovata" });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// Lista barbieri (admin)
app.get('/api/admin/barbieri', verificaToken, soloAdmin, async (req, res) => {
    const { sede_id } = req.query;
    try {
        let result;
        if (sede_id) {
            result = await pool.query(
                `SELECT b.id, b.nome, b.tipo, b.assente, b.motivo_assenza,
                        array_agg(t.giorno_settimana ORDER BY t.giorno_settimana) AS giorni_lavoro
                 FROM barbieri b
                 JOIN turni_rotazione t ON b.id=t.barbiere_id
                 WHERE t.sede_id=$1
                 GROUP BY b.id, b.nome, b.tipo, b.assente, b.motivo_assenza
                 ORDER BY b.nome`, [sede_id]
            );
        } else {
            result = await pool.query('SELECT id, nome, tipo, assente, motivo_assenza FROM barbieri ORDER BY nome');
        }
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});

// SEGNA BARBIERE COME ASSENTE (con data e durata opzionale)
app.post('/api/admin/barbiere-assente', verificaToken, soloAdmin, async (req, res) => {
    const { barbiere_id, motivo, data_inizio, giorni } = req.body;
    if (!barbiere_id) return res.status(400).json({ error: "Manca barbiere_id" });

    try {
        // Usa ora italiana — CURRENT_DATE/CURRENT_TIME sul server UTC darebbe orari sbagliati
        const italianNow = new Date().toLocaleString('sv-SE', { timeZone: 'Europe/Rome' }).replace(' ', 'T');
        const oggi = italianNow.slice(0, 10);
        const italianTime = italianNow.slice(11, 16);
        const inizio = data_inizio || oggi;

        // Calcola data fine (se specificati i giorni)
        let fine = null;
        if (giorni && giorni > 0) {
            const d = new Date(inizio + 'T12:00:00Z');
            d.setDate(d.getDate() + giorni - 1);
            fine = d.toISOString().split('T')[0];
        }

        const isOggi = inizio <= oggi;
        const infoObj = {
            tipo: 'assente',
            stato: isOggi ? 'attivo' : 'programmato',
            inizio,
            fine,
            motivo: motivo || 'Assente'
        };

        if (isOggi) {
            // Attivazione immediata
            await pool.query(
                'UPDATE barbieri SET assente = true, motivo_assenza = $1 WHERE id = $2',
                [JSON.stringify(infoObj), barbiere_id]
            );

            // Trova appuntamenti da cancellare nel periodo (usa data/ora italiana come parametri)
            const appParams = [barbiere_id, oggi, italianTime];
            let appQuery = `SELECT p.id, p.cliente_uuid, p.data, p.ora, b.nome AS barbiere_nome, sv.nome AS servizio_nome
                 FROM prenotazioni p
                 JOIN barbieri b ON p.barbiere_id = b.id
                 JOIN servizi sv ON p.servizio_id = sv.id
                 WHERE p.barbiere_id = $1 AND p.stato = 'attivo'
                 AND (p.data > $2::date OR (p.data = $2::date AND p.ora >= $3::time))`;
            if (fine) { appQuery += ` AND p.data <= $4::date`; appParams.push(fine); }
            const appuntamenti = await pool.query(appQuery, appParams);

            // Notifica clienti registrati
            let notificheInviate = 0;
            for (const app of appuntamenti.rows) {
                if (app.cliente_uuid) {
                    const dateObj = new Date(app.data + 'T12:00:00');
                    const giorniNomi = ['Dom','Lun','Mar','Mer','Gio','Ven','Sab'];
                    const mesi = ['Gennaio','Febbraio','Marzo','Aprile','Maggio','Giugno','Luglio','Agosto','Settembre','Ottobre','Novembre','Dicembre'];
                    const dataFormattata = `${giorniNomi[dateObj.getDay()]} ${dateObj.getDate()} ${mesi[dateObj.getMonth()]}`;
                    const messaggio = `Ci scusiamo per il disagio. Il tuo appuntamento di **${dataFormattata}** alle **${app.ora.slice(0,5)}** con **${app.barbiere_nome}** per il servizio di **${app.servizio_nome}** è stato cancellato perché il barbiere non è disponibile.\n\nTi invitiamo a prenotare un nuovo appuntamento.`;
                    await pool.query('INSERT INTO notifiche (cliente_uuid, messaggio) VALUES ($1, $2)', [app.cliente_uuid, messaggio]);
                    notificheInviate++;
                }
            }

            // Marca cancellato (non elimina) — così è ripristinabile alla riattivazione
            const delParams = [barbiere_id, oggi, italianTime];
            let delQuery = `UPDATE prenotazioni SET stato = 'cancellato'
                 WHERE barbiere_id = $1 AND stato = 'attivo'
                 AND (data > $2::date OR (data = $2::date AND ora >= $3::time))`;
            if (fine) { delQuery += ` AND data <= $4::date`; delParams.push(fine); }
            const eliminati = await pool.query(delQuery, delParams);

            res.json({
                success: true,
                eliminati: eliminati.rowCount,
                notifiche_inviate: notificheInviate,
                messaggio: `Barbiere segnato come assente. ${eliminati.rowCount} appuntamenti cancellati e ${notificheInviate} clienti notificati.`
            });
        } else {
            // Programmazione futura: non imposta assente=true, solo salva il piano
            await pool.query(
                'UPDATE barbieri SET assente = false, motivo_assenza = $1 WHERE id = $2',
                [JSON.stringify(infoObj), barbiere_id]
            );
            const dataFmt = new Date(inizio + 'T12:00:00Z').toLocaleDateString('it-IT', { day: 'numeric', month: 'long' });
            res.json({ success: true, messaggio: `Assenza programmata per il ${dataFmt}.` });
        }
    } catch (err) {
        console.error("Errore assenza:", err);
        res.status(500).json({ error: "Errore nella gestione dell'assenza" });
    }
});

// PERMESSO TEMPORANEO BARBIERE (con data, ora e durata in minuti)
app.post('/api/admin/barbiere-permesso', verificaToken, soloAdmin, async (req, res) => {
    const { barbiere_id, data_inizio, ora_inizio, minuti } = req.body;
    if (!barbiere_id || !minuti) return res.status(400).json({ error: "Manca barbiere_id o minuti" });
    try {
        // Ora italiana corrente — evita shift UTC (server è UTC, Italia è UTC+2)
        const italianNow = new Date().toLocaleString('sv-SE', { timeZone: 'Europe/Rome' }).replace(' ', 'T');
        const oggi = italianNow.split('T')[0];
        const dataI = data_inizio || oggi;
        const oraI = ora_inizio || italianNow.slice(11, 16);

        // Calcolo aritmetico per oraFine — nessuna conversione Date che causa shift UTC
        const [hI, mI] = oraI.split(':').map(Number);
        const totalMin = hI * 60 + mI + parseInt(minuti);
        const endH = Math.floor(totalMin / 60) % 24;
        const endM = totalMin % 60;
        const oraFineStr = `${String(endH).padStart(2,'0')}:${String(endM).padStart(2,'0')}`;

        // Confronto su stringa italiana — no Date UTC
        const isOra = `${dataI}T${oraI}:00` <= italianNow;

        // Salva come stringhe locali senza 'Z' — il browser italiano le legge correttamente
        const infoObj = {
            tipo: 'permesso',
            stato: isOra ? 'attivo' : 'programmato',
            inizio: `${dataI}T${oraI}:00`,
            fine: `${dataI}T${oraFineStr}:00`
        };

        await pool.query(
            'UPDATE barbieri SET assente = $1, motivo_assenza = $2 WHERE id = $3',
            [isOra, JSON.stringify(infoObj), barbiere_id]
        );

        // Cerca appuntamenti da cancellare per inviare notifiche prima di aggiornare
        const appsPermesso = await pool.query(
            `SELECT p.id, p.cliente_uuid, p.data, p.ora, bv.nome AS barbiere_nome, sv.nome AS servizio_nome
             FROM prenotazioni p
             JOIN barbieri bv ON p.barbiere_id = bv.id
             JOIN servizi sv ON p.servizio_id = sv.id
             WHERE p.barbiere_id = $1 AND p.data = $2 AND p.stato = 'attivo'
             AND p.ora >= $3 AND p.ora < $4`,
            [barbiere_id, dataI, oraI, oraFineStr]
        );

        for (const app of appsPermesso.rows) {
            if (app.cliente_uuid) {
                const dateObj = new Date(app.data + 'T12:00:00');
                const giorniNomi = ['Domenica','Lunedì','Martedì','Mercoledì','Giovedì','Venerdì','Sabato'];
                const mesi = ['Gennaio','Febbraio','Marzo','Aprile','Maggio','Giugno','Luglio','Agosto','Settembre','Ottobre','Novembre','Dicembre'];
                const dataFormattata = `${giorniNomi[dateObj.getDay()]} ${dateObj.getDate()} ${mesi[dateObj.getMonth()]}`;
                const messaggio = `Ci scusiamo per il disagio. Il tuo appuntamento di **${dataFormattata}** alle **${app.ora.slice(0,5)}** con **${app.barbiere_nome}** per il servizio di **${app.servizio_nome}** è stato cancellato perché il barbiere è in permesso.\n\nTi invitiamo a prenotare un nuovo appuntamento.`;
                await pool.query('INSERT INTO notifiche (cliente_uuid, messaggio) VALUES ($1, $2)', [app.cliente_uuid, messaggio]);
            }
        }

        await pool.query(
            `UPDATE prenotazioni SET stato = 'cancellato'
             WHERE barbiere_id = $1 AND data = $2 AND stato = 'attivo'
             AND ora >= $3 AND ora < $4`,
            [barbiere_id, dataI, oraI, oraFineStr]
        );

        const ore = Math.floor(minuti / 60);
        const min = minuti % 60;
        const durata = ore > 0 ? `${ore}h${min > 0 ? ` ${min}min` : ''}` : `${min}min`;

        if (isOra) {
            res.json({ success: true, messaggio: `Barbiere in permesso per ${durata}` });
        } else {
            const dataFmt = new Date(dataI + 'T12:00:00').toLocaleDateString('it-IT', { day: 'numeric', month: 'long' });
            res.json({ success: true, messaggio: `Permesso programmato per il ${dataFmt} alle ${oraI} (${durata})` });
        }
    } catch (err) {
        res.status(500).json({ error: "Errore nella gestione del permesso" });
    }
});

// RIATTIVA BARBIERE
app.post('/api/admin/barbiere-presente', verificaToken, soloAdmin, async (req, res) => {
    const { barbiere_id } = req.body;
    if (!barbiere_id) return res.status(400).json({ error: "Manca barbiere_id" });
    try {
        const italianNow = new Date().toLocaleString('sv-SE', { timeZone: 'Europe/Rome' }).replace(' ', 'T');
        const italianDate = italianNow.slice(0, 10);
        const italianTime = italianNow.slice(11, 16);

        // Trova appuntamenti cancellati futuri da ripristinare (usa ora italiana)
        const daRipristinare = await pool.query(
            `SELECT p.id, p.cliente_uuid, p.data, p.ora, b.nome AS barbiere_nome, sv.nome AS servizio_nome
             FROM prenotazioni p
             JOIN barbieri b ON p.barbiere_id = b.id
             JOIN servizi sv ON p.servizio_id = sv.id
             WHERE p.barbiere_id = $1 AND p.stato = 'cancellato'
             AND (p.data > $2::date OR (p.data = $2::date AND p.ora >= $3::time))`,
            [barbiere_id, italianDate, italianTime]
        );

        if (daRipristinare.rows.length > 0) {
            // Ripristina gli appuntamenti a 'attivo'
            await pool.query(
                `UPDATE prenotazioni SET stato = 'attivo'
                 WHERE barbiere_id = $1 AND stato = 'cancellato'
                 AND (data > $2::date OR (data = $2::date AND ora >= $3::time))`,
                [barbiere_id, italianDate, italianTime]
            );

            // Notifica ogni cliente del ripristino
            for (const app of daRipristinare.rows) {
                if (app.cliente_uuid) {
                    const dateObj = new Date(app.data + 'T12:00:00');
                    const giorniNomi = ['Domenica','Lunedì','Martedì','Mercoledì','Giovedì','Venerdì','Sabato'];
                    const mesi = ['Gennaio','Febbraio','Marzo','Aprile','Maggio','Giugno','Luglio','Agosto','Settembre','Ottobre','Novembre','Dicembre'];
                    const dataFormattata = `${giorniNomi[dateObj.getDay()]} ${dateObj.getDate()} ${mesi[dateObj.getMonth()]}`;
                    const messaggio = `Buone notizie! Il tuo appuntamento di **${dataFormattata}** alle **${app.ora.slice(0,5)}** con **${app.barbiere_nome}** per il servizio di **${app.servizio_nome}** è stato ripristinato. Il barbiere è nuovamente disponibile.\n\nTi aspettiamo!`;
                    await pool.query('INSERT INTO notifiche (cliente_uuid, messaggio) VALUES ($1, $2)', [app.cliente_uuid, messaggio]);
                }
            }
        }

        // Riattiva il barbiere
        await pool.query('UPDATE barbieri SET assente = false, motivo_assenza = NULL WHERE id = $1', [barbiere_id]);

        res.json({
            success: true,
            messaggio: `Barbiere riattivato. ${daRipristinare.rows.length} appuntamenti ripristinati.`,
            ripristinati: daRipristinare.rows.length
        });
    } catch (err) {
        res.status(500).json({ error: "Errore" });
    }
});