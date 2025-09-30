
# Corso Python — Progetto finale

**Titolo progetto principale:** Nmap GUI Assistant  
**Titolo progetto di backup:** Random List Picker

---

## Sommario
Per il progetto finale del corso di Python ho scelto due idee.  
Il progetto principale prevede la creazione di un’applicazione grafica che semplifica l’uso di **Nmap**, uno strumento per analizzare e verificare reti informatiche.  
Come alternativa, nel caso il tempo non fosse sufficiente, svilupperò un’applicazione più semplice che permette di gestire **liste di elementi** ed estrarre a caso un elemento da esse, con probabilità personalizzabili.

---

## 1. Progetto principale: **Nmap GUI Assistant**

### Obiettivo
Realizzare un programma con interfaccia grafica (usando **Kivy**) che renda più facile l’esecuzione di alcune scansioni di rete di base.  
L’idea è fornire dei pulsanti e dei campi semplici da compilare al posto della riga di comando, così che anche chi non conosce bene Nmap possa fare alcune verifiche comuni.

### Funzionalità previste
- Inserire un indirizzo IP o un intervallo di indirizzi.
- Avviare alcune scansioni predefinite, ad esempio:
  - controllare quali computer sono attivi in rete,
  - cercare porte aperte,
  - riconoscere i servizi principali in esecuzione.
- Mostrare i risultati in modo chiaro nella finestra del programma.
- Salvare i risultati in un file (ad esempio in formato JSON o testo).

### Nota importante
Il programma ha uno scopo **educativo** e può essere usato solo su reti proprie o con autorizzazione.  
Non deve essere utilizzato per attività non consentite.

---

## 2. Progetto di backup: **Random List Picker**

### Obiettivo
Creare un’app grafica che permetta di gestire liste di elementi testuali (come nomi, parole o oggetti).  
Ogni elemento avrà un “peso”, cioè una probabilità diversa di essere estratto. Le liste vengono salvate in un file per poterle riutilizzare.

### Funzionalità previste
- Creare e nominare nuove liste.
- Aggiungere e rimuovere elementi, assegnando a ciascuno un peso.
- Estrarre un elemento a caso rispettando le probabilità.
- Salvare e caricare le liste in automatico da file JSON.

Esempio: una lista di nomi con probabilità diverse di essere scelti.
