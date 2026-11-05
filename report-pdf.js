// ==========================================
// REPORT PDF DELL'ARCHIVIO OPERAZIONI (Console Developer → Esporta Report)
// ==========================================
// A4 verticale: intestazione nero/oro, riepilogo per tipo di azione, tabella Data | Ora | Tipo | Descrizione
// con righe alternate, intestazione ripetuta a ogni pagina e numero di pagina nel piè.
const PDFDocument = require('pdfkit');

const MESI = ['Gennaio', 'Febbraio', 'Marzo', 'Aprile', 'Maggio', 'Giugno', 'Luglio', 'Agosto', 'Settembre', 'Ottobre', 'Novembre', 'Dicembre'];
const NERO = '#0A0A0A';
const ORO = '#D4AF37';
const GRIGIO_TESTO = '#333333';
const GRIGIO_RIGA = '#F4F1E8';
const BORDO = '#D9D2BC';

const MARGINE = 40;
const COLONNE = [
    { titolo: 'Data', larghezza: 64 },
    { titolo: 'Ora', larghezza: 38 },
    { titolo: 'Tipo di azione', larghezza: 118 },
    { titolo: 'Descrizione', larghezza: 0 }, // il resto della pagina
];
const PAD = 6;

// righe: [{ data: 'YYYY-MM-DD', ora: 'HH:MM', azione_etichetta, descrizione, righe: [] }] in ordine cronologico
const reportPdf = (righe, anno, mese) => new Promise((risolvi, rifiuta) => {
    const doc = new PDFDocument({
        size: 'A4',
        margins: { top: MARGINE, bottom: MARGINE + 10, left: MARGINE, right: MARGINE },
        bufferPages: true,
        info: { Title: `Report operazioni - ${MESI[mese - 1]} ${anno}`, Author: 'Bulldog Barber Shop', Subject: 'Archivio operazioni della Console Developer' },
    });
    const pezzi = [];
    doc.on('data', (c) => pezzi.push(c));
    doc.on('end', () => risolvi(Buffer.concat(pezzi)));
    doc.on('error', rifiuta);

    const larghezzaPagina = doc.page.width - MARGINE * 2;
    COLONNE[3].larghezza = larghezzaPagina - COLONNE.slice(0, 3).reduce((s, c) => s + c.larghezza, 0);
    const fondo = () => doc.page.height - doc.page.margins.bottom;

    // ── Intestazione del documento ──
    doc.rect(0, 0, doc.page.width, 92).fill(NERO);
    doc.fillColor(ORO).font('Helvetica-Bold').fontSize(10).text('BULLDOG BARBER SHOP', MARGINE, 30, { characterSpacing: 3 });
    doc.fillColor('#FFFFFF').font('Helvetica-Bold').fontSize(19).text('Report operazioni di manutenzione', MARGINE, 47);
    const adesso = new Date().toLocaleString('it-IT', { timeZone: 'Europe/Rome', day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
    doc.fillColor(GRIGIO_TESTO).font('Helvetica-Bold').fontSize(13).text(`${MESI[mese - 1]} ${anno}`, MARGINE, 112);
    doc.font('Helvetica').fontSize(9).fillColor('#777777')
        .text(`Generato il ${adesso.replace(',', ' alle')} · Console Developer`, MARGINE, 130);

    // ── Riepilogo per tipo ──
    const conteggio = {};
    for (const r of righe) conteggio[r.azione_etichetta] = (conteggio[r.azione_etichetta] || 0) + 1;
    let y = 152;
    doc.roundedRect(MARGINE, y, larghezzaPagina, 20 + Math.max(1, Object.keys(conteggio).length) * 13, 4).fillAndStroke('#FBF8EF', BORDO);
    doc.fillColor(NERO).font('Helvetica-Bold').fontSize(10).text(`Totale operazioni: ${righe.length}`, MARGINE + 10, y + 8);
    y += 22;
    doc.font('Helvetica').fontSize(9).fillColor(GRIGIO_TESTO);
    for (const [tipo, n] of Object.entries(conteggio)) {
        doc.text(`${tipo}: ${n}`, MARGINE + 10, y);
        y += 13;
    }
    y += Object.keys(conteggio).length ? 16 : 29;

    // ── Tabella ──
    const intestazioneTabella = () => {
        doc.rect(MARGINE, y, larghezzaPagina, 22).fill(ORO);
        let x = MARGINE;
        doc.fillColor(NERO).font('Helvetica-Bold').fontSize(9);
        for (const c of COLONNE) {
            doc.text(c.titolo.toUpperCase(), x + PAD, y + 7, { width: c.larghezza - PAD * 2, characterSpacing: 0.5 });
            x += c.larghezza;
        }
        y += 22;
    };
    intestazioneTabella();

    if (righe.length === 0) {
        doc.rect(MARGINE, y, larghezzaPagina, 34).fill(GRIGIO_RIGA);
        doc.fillColor('#777777').font('Helvetica-Oblique').fontSize(10)
            .text('Nessuna operazione registrata in questo mese.', MARGINE, y + 12, { width: larghezzaPagina, align: 'center' });
    }

    righe.forEach((r, i) => {
        const valori = [r.data.split('-').reverse().join('/'), r.ora, r.azione_etichetta, r.descrizione];
        // Altezza misurata con il carattere reale di ogni colonna (il tipo è in grassetto, più largo)
        const alte = valori.map((v, k) => doc.font(k === 2 ? 'Helvetica-Bold' : 'Helvetica').fontSize(9)
            .heightOfString(String(v), { width: COLONNE[k].larghezza - PAD * 2 }));
        const altezza = Math.max(...alte) + PAD * 2;
        if (y + altezza > fondo()) {
            doc.addPage();
            y = doc.page.margins.top;
            intestazioneTabella();
        }
        if (i % 2 === 1) doc.rect(MARGINE, y, larghezzaPagina, altezza).fill(GRIGIO_RIGA);
        doc.moveTo(MARGINE, y + altezza).lineTo(MARGINE + larghezzaPagina, y + altezza).lineWidth(0.5).strokeColor(BORDO).stroke();
        let x = MARGINE;
        valori.forEach((v, k) => {
            doc.fillColor(k === 2 ? '#8A6D0B' : GRIGIO_TESTO).font(k === 2 ? 'Helvetica-Bold' : 'Helvetica').fontSize(9)
                .text(String(v), x + PAD, y + PAD, { width: COLONNE[k].larghezza - PAD * 2 });
            x += COLONNE[k].larghezza;
        });
        y += altezza;
    });

    // ── Piè di pagina su tutte le pagine ──
    const pagine = doc.bufferedPageRange();
    for (let i = 0; i < pagine.count; i++) {
        doc.switchToPage(i);
        // Il piè sta sotto il margine inferiore: senza azzerarlo pdfkit aprirebbe una pagina nuova
        doc.page.margins.bottom = 0;
        const yPie = doc.page.height - MARGINE + 6;
        doc.font('Helvetica').fontSize(8).fillColor('#999999')
            .text(`Bulldog Barber Shop · Report operazioni ${MESI[mese - 1]} ${anno}`, MARGINE, yPie, { width: larghezzaPagina / 2, lineBreak: false })
            .text(`Pagina ${i + 1} di ${pagine.count}`, MARGINE + larghezzaPagina / 2, yPie, { width: larghezzaPagina / 2, align: 'right', lineBreak: false });
    }
    doc.end();
});

module.exports = { reportPdf };
