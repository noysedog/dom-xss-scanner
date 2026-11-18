# DOM XSS Scanner 2.0

Estensione Firefox (Manifest v2) che segue i valori controllabili dall'utente
(query, hash, path, referrer, window.name, cookie, storage, postMessage)
fino ai sink pericolosi e mostra i risultati in un pannello DevTools.

## Installazione (temporanea)
1. `about:debugging#/runtime/this-firefox`
2. "Carica componente aggiuntivo temporaneo" e scegli `manifest.json`.
3. Apri una pagina, poi DevTools > scheda "DOM XSS".

## Prova rapida
`python3 -m http.server 8000` nella cartella del progetto e apri
`http://localhost:8000/test/lab.html?name=Mario&t=1#benvenuto`.
Attesi: innerHTML (hash), insertAdjacentHTML (query), setTimeout(stringa).
Il pulsante "Invia postMessage" genera il terzo caso.

## Architettura
- `page/page-script.js`: caricato anche come content script, espone il motore; `content/relay.js` lo inietta come `<script>` inline a document_start (esecuzione sincrona, prima degli script della pagina) e ripiega su `src` se la CSP blocca l'inline.
- il motore: sources, sink, taint per valore, finding.
- `background/background.js`: stato per tab, badge, hub verso il pannello.
- `devtools/`: pannello (nessun innerHTML, nessun handler inline).

## Interpretare i finding
- alta confidenza: il valore contiene metacaratteri (`< > " ' = ( )` ...) oppure il sink esegue codice.
- solo riflesso: il testo compare nel sink ma senza sintassi pericolosa; verifica a mano.
Un finding indica un flusso, non una vulnerabilità confermata: controlla sempre se la pagina sanifica.

## Limiti noti
- Non si possono agganciare i setter di `location` (href, assign, replace): navigazioni e open redirect via location non sono visibili. `window.open` sì.
- Il taint è per sottostringa: trasformazioni pesanti del valore (hash, cifratura, slice corto) lo perdono.
- Iframe same-origin creati dalla pagina hanno prototipi nuovi (il relay li aggancia se caricano un documento, non quando la pagina usa `contentWindow` direttamente).
- `hookEval` (in `page-script.js`, oggetto CFG): sostituire `eval` rende indiretta ogni eval diretta; mettilo a `false` se un sito smette di funzionare.
- Con CSP molto restrittive lo script iniettato può essere bloccato: il pannello mostra un avviso.
- `$()` con stringa/selettore di jQuery non è agganciato (html/append/... sì).
