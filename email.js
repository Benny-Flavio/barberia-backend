// ==========================================
// EMAIL TRANSAZIONALI (Resend, https://resend.com) — API HTTP, nessuna dipendenza aggiuntiva
// ==========================================
// Variabili d'ambiente (su Render → Environment):
//   RESEND_API_KEY   chiave API di Resend
//   EMAIL_MITTENTE   es. "Bulldog Barber Shop <notifiche@tuodominio.it>" — dominio verificato su Resend
// Senza queste due variabili l'invio è disattivato: i messaggi restano comunque visibili nell'app.

const RESEND_URL = 'https://api.resend.com/emails';

const emailConfigurata = () => !!(process.env.RESEND_API_KEY && process.env.EMAIL_MITTENTE);

const escapeHtml = (s) => String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

// I messaggi usano **grassetto** e \n come nell'app
const testoHtml = (m) => escapeHtml(m)
    .replace(/\*\*(.+?)\*\*/g, '<strong style="color:#ffffff">$1</strong>')
    .replace(/\n/g, '<br>');
const testoSemplice = (m) => String(m).replace(/\*\*(.+?)\*\*/g, '$1');

const templateHtml = (titolo, messaggio) => `<!doctype html>
<html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0A0A0A;font-family:Arial,Helvetica,sans-serif">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0A0A0A;padding:32px 16px">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#141414;border:1px solid #3a3215;border-radius:16px">
        <tr><td style="padding:28px 28px 8px;text-align:center">
          <div style="color:#D4AF37;font-size:12px;font-weight:bold;letter-spacing:4px">BULLDOG BARBER SHOP</div>
        </td></tr>
        <tr><td style="padding:12px 28px 0">
          <h1 style="margin:0;color:#ffffff;font-size:20px;line-height:28px">${escapeHtml(titolo)}</h1>
        </td></tr>
        <tr><td style="padding:14px 28px 28px;color:#BBBBBB;font-size:15px;line-height:23px">${testoHtml(messaggio)}</td></tr>
        <tr><td style="padding:16px 28px;border-top:1px solid #222;color:#666;font-size:12px;line-height:18px">
          Trovi questo messaggio anche nella sezione Messaggi dell'app.
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;

// Invia una email; lancia un errore se Resend la rifiuta o non risponde entro 10 s.
// Senza configurazione non fa nulla (restituisce false): il modulo non lancia mai all'avvio.
const inviaEmail = async ({ a, oggetto, titolo, messaggio }) => {
    if (!emailConfigurata()) {
        console.warn('Email non inviata: RESEND_API_KEY / EMAIL_MITTENTE non impostate');
        return false;
    }
    const res = await fetch(RESEND_URL, {
        method: 'POST',
        headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
            from: process.env.EMAIL_MITTENTE,
            to: [a],
            subject: oggetto,
            html: templateHtml(titolo, messaggio),
            text: `${titolo}\n\n${testoSemplice(messaggio)}\n\n— Bulldog Barber Shop`,
        }),
        signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) {
        const corpo = await res.json().catch(() => ({}));
        throw new Error(`Resend ${res.status}: ${corpo.message || corpo.name || 'errore'}`);
    }
};

module.exports = { emailConfigurata, inviaEmail };
