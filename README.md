# Razvoj namenskog softvera

## Arhitektura softvera

<div style="text-align: justify">

**Arhitektura softvera** predstavlja sponu između poslovnih i tehničkih zahteva u skladu sa planiranom namenom sistema, i različitim scenarijima upotrebe sistema. **Cilj** arhitekture softvera je identifikacija zahteva koji utiču na strukturni izgled aplikacije i predstava te struktura sistema, ali tako da se sakriju detalji implementacije. **Parametri kvaliteta** su ukupni faktori koji utiču na *run-time* ponašanje sistema, utiču na dizajn sistema i korisničko iskustvo u upotrebi sistema.

- **Arhitekturalni stil** predstavlja odraz/prikaz sistema/aplikacije na najvišem nivou apstrakcije. 
- **Arhitekturalni model/obrazac** (*architectural pattern*) predstavlja način implementacije određenog stila arhitekture. 
- **Model/obrazac projektovanja** (*design pattern*) je način na koji se rešava standardizovani problem.

> [!NOTE]
> Arhitektura softverskog sistema obično nije ograničena na upotrebu jednog arhitekturalnog stila, već je obično data kao kombinacija više arhitekturalnih stilova koji opisuju čitav sistem iz različitih uglova.

### Arhitekturalni stilovi

**Arhitekturalni stil** opisuje najviši nivo granularnosti sistema i odgovarajuće entitete i elemente sistema, kao i relacije i interakcije između njih. **Cilj** primene arhitekturalnih stilova je da se koristi poznati pristup u rešavanju standardnih problema u nekom od domena.

Arhitektura softvera distribuiranog sistema podrazumeva:
- Fizički razmeštaj (*deployment view*)
- Arhitekturu sistema (*system and node view*)
- Opis hardvera i softvera (*hardware and software view*)
- Opis komunikacije (*messaging view*)
- Management life-cycle (*management view*)
- Zaštitu i bezbednost (*security view*)
- Održavanje i ažuriranje (*maintenance view*)

Svaki od arhitekturalnih stilova odnosi se na neki od domena/kategorija implementacije sistema.

- **Slojevita arhitektura** - svaki sloj ima svoju funkcionalnost i pruža servis drugom sloju, obično se koristi za opis modela komunikacije (OSI, TCP/IP).

- **Objektno-orijentisana arhitektura** - softver se organizuje u logički nezavisnim komponentama koju su distribuirane na različitim fizičkim *node*-ovima. Podrazumeva se realizacije komponenti softvera i mehanizam njihove interakcije u formi poziva udaljenih/lokalnih procedura ili metoda ovih objekata (RPC - *Remote Procedure Call* i RMI - *Remote Method Invocation*).
    - **Sinhroni poziv** blokiranje procesa i čekanje.
    - **Asinhroni poziv** ne podrazumeva blokiranje.
    - ***Callback* mehanizam** predstavlja funkciju koja se poziva nakon što druga funkcija završi izvršavanje.

- **Arhitektura bazirana na komponentama** predstavlja pristup koji uključuje projektovanje i razvoj komponenti softvera koje se mogu ponovo koristiti (*reusable components*) koje enkapsuliraju jednu funkcionalnost ili grupu funkcionalnosti.

- **Servisno orijentisana arhitektura** se uglavnom definiše kao korišćenje *web* servisa. Princip upotrebe web servisa uključuje:
    - *Service provider* - opis servisa šalje registratoru servisa
    - *Service consumer* od registratora uzima adresu servisa (URL) i opis servisa (WSDL *file*) koje koristi da bi klijent proces pristupio udaljenom servisu na strani *service provider*-a.

- ***Data-centric* arhitektura** se uglavnom koristi za pristup podacima i njihovo ažuriranje. Interakcija između dislociranih procesa se obavlja kroz *read/write* zahteve za pristup podacima koji su organizovani u nekoj formi deljenog resursa ili aktivnog/pasivnog repozitorijuma.

- Kod ***Event-based* arhitekture** procesi međusobno komuniciraju kroz model propagacije događaja što omogućava da su komponente sistema labavo povezane. *Listener* dobija notifikaciju kada je *source* objavio poruku na određenom kanalu na koji je listener pretplaćen.

- ***Tiered* arhitektura** (N-*tier*) arhitektura podrazumeva opis distribuirane arhitekture sistema. *Tier*-i se mogu tretirati kao geo-lokacijske grupe/slojevi koji implementiraju jedan deo distribuirane funkcionalnosti sistema.

- ***Microservice* arhitektura** predstavlja skalabilan pristup lokalizacije funkcionalnosti pogodan kod realizacije distribuiranih funkcionalnosti. Funkcionalnost je data kroz kolaboraciju mikro-servisa.

### Arhitekturalni modeli/obrasci

**Arhitekturalni modeli** imaju značajan uticaj na razvoj koda, često utičući na razvoj aplikacije na horizontalan način (organizacija koda u okviru slojeva/modula) ili vertikalno (način procesiranja podataka koji se razmenjuju
između slojeva/modula).

- **OSI model** je arhitekturalni model za modeliranje računarske komunikacije. Koristi slojeviti model sa 7 slojeva uvodeći različite nivoe apstrakcije.

U softverskom inženjerstvu pojam **modela projektovanja** (*design pattern*) se odnosi na opšte prihvaćeno rešenje za određenu, poznatu, klasu problema koji se susreće pri projektovanju softvera.

- ***3-Tier*** sistem se sastoji od *data management* (baza podataka), aplikativnog (servera) i klijent (aplikacijski interfejs) dela.

    - ***Client-server***
    - ***Broker-based***
    - ***Peer-to-peer***

- ***Master-slave*** ovaj obrazac podrazumeva dve strane i odnosi se na asimetrični pristupni model.

- ***Model-View-Controller*** je arhitekturalni model baziran na delegiranju odgovornosti, čime se pojednostavljuje dizajn pojedinačnih komponenti.

    - **Model** - sadrži sve relevantne podatke i nema interakciju sa *View* komponentom.
    - **View** – podrazumeva reprezentaciju podataka i interfejs prema korisniku. Komunicira isključivo sa kontrolerom.
    - **Controller** - prima zahteve od korisnika, kontaktira model kako bi preuzeo potrebne podatke i zatim iste prezentuje korisniku preko *View* komponente.

- ***Pipe & Filter*** je model gde se svaki korak procesiranja je enkapsuliran u nezavisne *filter* komponente (*task*-ove) koji dobijaju podatke za procesiranje preko *pipe* komponenti.

- ***Messaging Patterns*** je *request/response* model koji podrazumeva slanje zahteva koji se procesira na prijemnoj strani, nakon čega se šalje odgovor.

    - ***Publish subscribe***
    - ***Queue-based***
    - ***Service-bus***

- ***Publish-Subscribe*** obezbeđuje mehanizam razmene poruka i *loosely-coupled* interakciju između *publisher*-a (pošiljaoca poruke) i *subscriber*-a (primaoca poruke). Pošiljalac nema informacije o primaocu poruke, već tu informaciju ima *message broker*.

- ***Message-Queuing*** je uprošćena forma *publish/subscribe* modela, gde imamo samo jednog *publisher*-a i *subscriber*-a koji čeka da poruka bude dostupna u *queue* menadžeru.

- ***Middleware*** arhitektura koristi se kao model pristupa udaljenom serveru/servisu/mikro-servisu. Obezbeđuje mehanizam pristupa, mehanizam perzistentne komunikacije, kontrolu i zaštitu pristupa, rutiranje, kontrolu transakcije, osobine komunikacije...

- ***Command-patterns*** podrazumeva set operacija, komandi, metoda ili akcija. Osnovni set operacija podrazumeva *create*, *read*, *update* i *delete* operacije.
    - *Resource-oriented* (*Data centric, remote data access*)
    - *Service-oriented* (*Processing centric, remote service access*)

### Arhitekturalni opisi 

- **4+1** - Podrazumeva prikaz arhitekture iz ugla:
    - logičkog prikaza (npr. objektni model)
    - prikaza procesa/tokova (konkurentnost i aspekti sinhronizacije)
    - fizičkog izgleda (mapiranje komponenti softvera u okviru hardverske arhitekture) 
    - procesa razvoja softvera (scenariji izvršavanja).

- ***Unified Modeling Language* (UML)** - podrazumeva tri prikaza modela sistema iz ugla 
    - funkcionalnih zahteva (iz ugla korisnika, scenarija izvršavanja...)
    - statičkog strukturalnog ugla (objekti, relacije, klase)
    - ponašanja i interakcije komponenti sistema (dijagrami sekvence, aktivnosti i stanja).


## Proces razvoja softvera

**Razvoj softvera** podrazumeva projektovanje, razvoj i održavanje softverskih sistema primenjujući tehnološka dostignuća i znanja iz oblasti računarstva, inženjerstva, upravljanja projektima i iz drugih oblasti, pri čemu se podrazumeva *trade-off* pristup.

**Troškovi razvoja** zavise od procesa koji se sprovodi da bi se došlo do željenog rešenja. Procena troškova je izuzetno kompleksna jer sam proces podrazumeva puno različitih faza koje se sprovode jednom ili više puta. Kod sistema koji su projektovani za dugotrajnu eksploataciju **troškovi održavanja** su nekoliko puta ili desetinama puta veći od samih troškova razvoja.

Svi pristupi dele iste korake tj. faze u razvoju: zahtevi, projektovanje, implementacija, testiranje i održavanje, dok od modela zavisi kako će se te faze kombinovati i u kom redosledu. Svaka faza u razvoju treba da ima jasan set koraka koji treba izvršiti (plan) i jasan cilj koji omogućava analizu i reviziju rešenja (ishod).

Faze Software Development Life Cycle (SDLC)
    
- Planiranje i definisanje zahteva
- Projektovanje proizvoda
- Razvoj softvera
- Kodiranje i testiranje
- Integracija i testiranje
- Eksploatacija i održavanje

Aktivnosti vezane za proces razvoja
- Analiza zahteva
- Projektovanje
- Planiranje testiranja
- Verifikacija i validacija
- Analiza kvaliteta
- Razvoj dokumentacije

### Modeli razvoja softvera 

- ***Ad-Hoc* pristup** je model kreiranje softvera bez bilo kakve formalne procedure, pristupa ili procesa.

- ***Code and Fix*** je model kod koga se problemi rešavaju "usput". Primenljivo jedino kod malih projekata ili kod razvoja funkcionalnog prototipa sistema.

- ***Waterfall*** predstavlja model kod koga svaka faza mora biti završena pre započinjanja nove faze.

- **Iterativni model** polazi od malog podskupa zahteva, nakon čega se u svakoj iteraciji dodaju novi funkcionalni zahtevi.

    > **Iteracija** se odnosi na implementaciju dela funkcionalnosti na nivou čitavog sistema.

- **Inkrementalni model** podrazumeva da se sistem implementira u formi više inkrementalnih ciklusa, pri čemu se u svakom od ciklusa implementira deo zahteva. Podrazumeva više *waterfall* modela za svaki od inkremenata softvera.

    > **Inkrement** se odnosi sa razvoj dela sistema/softvera koji može biti zasebni softverski modul.

- **Spiralni model** je kombinacija iterativnog i nekog sekvencijalnog modela (npr. waterfall) sa akcentom na analizi rizika. Omogućava inkrementalno poboljšanje ili *release* proizvoda kroz svaku od spiralnih iteracija.

- **Rapid Development** predstavlja model koji se fokusira na prikupljanju zahteva korisnika i testiranju prototipa od strane korisnika. Prototip je radni primerak sistema koji je funkcionalno ekvivalentan delu finalnog proizvoda.

- **Evolutivni razvoj prototipa sistema** predstavlja razvoj najprostijeg inicijalnog prototipa sistema. Postupak unapređenja je evolutivni, tj. zahtevi sistema nisu apriori poznati u čemu je i razlika u odnosu na razvoj u fazama.

- **Diktirani razvoj**:

    - ***Fit-to-schedule*** - Razvoj je diktiran datumom isporuke i određuje šta od zahteva može da se uklopi u vremenski okvir.
    - ***Fit-to-features/quality*** - Isporuka je diktirana kada određeni skup funkcija bude realizovan.

- ***Agile* SDLC** predstavlja kombinaciju iterativnog i inkrementalnog pristupa za rapidni razvoj novih *feature*-a uz participaciju klijenta. *Software release* je dat kroz seriju iterativnih ciklusa koji svaki uključuje faze analize, projektovanja, razvoja i testiranja softvera. Uloge u procesu razvoja su vlasnik projekta (*project owner*), *scrum master* (upravlja procesom) i razvojni tim koji implementira faze ciklusa (*sprint*).


## Model namenskog sistema

**Osnovni model** namenskog sistema uključuje hardver sistema, sistemski i aplikativni softver.

Na osnovu funkcionalne specifikacije i performansi namenski sistemi se dele na: 
- *Stand-alone* sisteme ne zahtevaju vezu sa *host* sistemom za svoj rad i mogu koristiti povezani uređaj za prikaz, kontrolu ili pobudu namenskog sistema.
- Sisteme za rad u realnom vremenu - omogućavaju projektovanje sistema u skladu sa funkcionalnom specifikacijom koja uvodi ili razmatra i vremenske kriterijume ili okvire izvršavanja. 
- Mrežne namenske sisteme - koriste različite komunikacione tehnologije za pristup resursima i integraciju.
- Mobilne namenske sisteme - odnosi se na mobilne uređaje, telefone, PDA uređaje, nosive uređaje....

Klasifikacija namenskih sistema prema osobinama ili performansama hardverske platforme:

- ***Small-scale*** sistemi bazirani na 8, 16-bitnom mikrokontroleru, koji je često baterijski napajan. Imaju podršku IDE za cross-development. (*deeply-embedded applications*) 

- ***Medium-scale*** sistemi bazirani na 16, 32-bitnom mikrokontroleru koji je sposoban za mrežnu komunikaciju. Često imaju podršku OS, RTOS i IDE. Tehnologije za razvoj koda su Java, C, C++... (*networked embedded systems and applications*)

- ***Large-scale*** (sofisticirani sistemi) podrazumevaju kompleksne sisteme, HW/SW co-design, FPGA/ASIC hardver. (*cutting-edge applications*)

Smanjena potrošnja sistema se može postići:

- redukcijom učestanosti (*frequency scaling*)
- smanjivanjem napona napajanja (*voltage scaling*)
- isključivanjem nekorišćenih modula (*sleep/LPM mods*)
- optimizacijom softvera kontrolera (*slack/idle-time/utilization management*)

**Model namenskog sistema** podrazumeva najviši nivo apstrakcije sistema koji definiše zajedničke osobine komponenti sistema. Najčešće se pri predstavi modela uvode neke generičke komponente modela (*operating system*, *drivers*, *middleware*...) Ove komponente modela su interfejsi ili slojevi koji uvode nove apstrakcije hardvera, softvera ili funkcionalnosti.

***Middleware*** je softver koji pruža interfejs između druga dva softvera, obično aplikativnog softvera i operativnog sistema ili drajvera uređaja i dela operativnog sistema. U opštoj terminologiji mogu se razlikovati dva tipa ***middleware***-a:

- **Sistemski *middleware*** – biblioteka programskih funkcija (API biblioteka) koja pruža sistemsku apstrakciju za razvoj aplikativnog softvera. Koristi se za povećavanje nivoa portabilnosti aplikativnog softvera.

- ***Middleware* za apstrakciju hardvera** – API biblioteka koja se ponaša kao HAL za integraciju na nivou hardverskih komponenti.

Primeri komunikacionih *middleware*-a:

- Komponente softvera pozicionirane između aplikacije i servisa operativnog sistema - *object request brokers* (ORBs), 
*remote procedure calls* (RPCs), *database/database access* servisi, audio i video servisi (*DirectX*, *DirectSound*), mrežni servisi (*Windows sockets*), *game engine*, ...

- *Message-oriented middleware* (MOM) - forma softverske i hardverske nadgradnje (*message server*) koja pruža podršku za slanje i prijem poruka u okviru distribuiranog sistema.

- *Event-based middleware* (ili *publish/subscribe*) nudi komunikaciju u formi razmene informacija (u formi notifikacije) o događajima. 

**Drajveri uređaja**:

- **Generički drajveri** služe za rad sa hardverom na ploči.

- **Drajveri specifični za arhitekturu** služe za rad sa hardverom koji je integrisan sa procesorom.

***Board Support Package*** (BSP) podrazumeva softver za inicijalizaciju i rad sa hardverskom platformom nudeći standardni interfejs operativnog sistema omogućavajući da se on izvršava na konkretnoj platformi. Time se postiže da OS bude nezavisan od platforme na kojoj se izvršava.    

> [!NOTE] 
> Ukoliko proizvođač platforme želi da se konkretni RTOS izvršava na njihovoj platformi mora razviti BSP koji to omogućava. Drajveri uređaja mogu biti deo operativnog sistema ili deo *board support package*-a (BSP).

***Hardware Abstraction Layer*** (HAL) je opšti pojam vezan za set rutina koje nude apstrakciju hardvera sistema. Sloj može da postoji nezavisno od postojanja OS/RTOS sloja. 


## Upravljanje softverskim projektima 

**Projekat** je skup ili grupa vremenski oročenih aktivnosti koji vode kreiranju jedinstvenog proizvoda ili servisa. **Upravljanje projektom** se odnosi na definisanje i postizanje ciljeva uz optimizaciju upotrebe resursa tokom trajanja projekta. Možemo razlikovati 5 aspekata koji definišu upravljanje projektom: vreme, cena, kvalitet, upotrebljivost, rizici.

Svaka faza projekta je definisana preko
    - kriterijuma za ulazak u fazu
    - kriterijuma za izlazak iz faze
    - potrebnih resursa za realizaciju
    - rezultata faze
    - izveštaja

Procena treba obavezno da uključi i **worst case analysis** (WCA), kao i planove za izlazak iz kritičnih situacija. ***Work Breakdown Structure*** (WBS) je tehnika koja se bazira na planiranju i organizaciji projekata u taskove i procenu resursa neophodnih za njihovu realizaciju. Osnovni koraci:

- **Identifikacija taskova** potrebnih za određeni projektni rezultat (*deliverable*), što uključuje i taskove za realizaciju internih ili međurezultata.
- **Sekvenca taskova** (*task/activity network diagram*) u smislu potencijala za paralelizacijom
- **Procena veličine problema** kod svakog zadatka (*task*-a)
- **Procena produktivnost** u pogledu realizacije konkretnog zadatka.
- **Procena vremena** potrebnog za realizaciju svakog taska.
- **Određivanje vremenske sekvence** svih taskova kao i neophodnih resursa za realizaciju svakog rezultata.

*Gantt*-ovi dijagrami se koriste za grafičku reprezentaciju vremena početka i kraja svakog pojedinačnog taska (vremenski dijagrami aktivnosti). Događaji mogu biti:

- ***Deliverables*** - rezultati vezani za konkretan rezultat projekta, verziju uređaja, verziju softvera... 

- ***Milestones*** su rezultati projektnih taskova, ili grupa taskova koji imaju definisan vremenski rok, a ujedno označavaju i trenutak početka narednih taskova.


## Razvojno okruženje i alati

Na ***host*** platformi se unosi, kompajlira i linkuje programski kod. Nakon što je kreiran, izvršni fajl isti se prenosi na ***target*** platformu gde se kod izvršava (ako *host* i *target* nisu isti uređaji).

- ***Native compiler*** generiše kod za izvršavanje na istoj platformi na kojoj je generisan.

- ***Cross compiler*** generiše kod koji se izvršava na drugoj platformi u odnosu na platformu na kojoj je generisan.

Postupak razvoja softvera podrazumeva bar 4 faze:

- **Unos programskog koda** podrazumeva poznavanja nekih detalja ciljne arhitekture, npr. organizacije memorije, veličine tipova podataka...
- **Kreiranje izvršnih fajlova** podrazumeva kompajliranje i linkovanje fajlova sa prekompajliranim bibliotekama programskih funkcija.
- **Prenos binarnih fajlova** može se obaviti preko JTAG, serijske ili Ethernet veze u formi jedinstvenog fajla koji može da sadrži i operativni sistem. Proces može da se inicira u formi boot rutine koja preuzima fajl sa TFTP servera ili slično.
- **Debagovanje izvršavanja** programskog koda podrazumeva preuzimanje informacija o njegovom izvršavanju sa *target* sistema.

Uobičajeno se u postupku razvoja koda i njegovog debagovanja koristi **integrisano razvojno okruženje** (IDE - *Integrated Development Environment*).

Proces kreiranja izvršnog koda na *host* sistemu uključuje:

- Unos koda aplikacije (C, C++, asembler...).
- Kreiranje `make` fajlova za *make* uslužni program (*utility*).
- Kompajler, asembler, interpreter.
- Linker koji prihvata objektne fajlove kao ulaz i proizvodi ili izvršni ***image* fajl** ili **objektni fajl** koji se može koristiti u procesu dodatnog linkovanja sa drugim objektnim fajlovima.
- Debagovanje izvršavanja koda u simulatoru ili na *target* sistemu preko host debagera.

> **IDE** podrazumeva integrisane sve nabrojane komponente.

Komandni fajl linkera daje instrukcije linkeru o tome kako da kombinuje objektne fajlove i gde da smesti binarni kod i podatke na *target* namenskom sistemu. Glavna funkcija **linkera** je da na osnovu više objektnih fajlova kreira: 

- **Realokatibilni objektni fajl** (*relocatable object file*) se linkuje u izvršni fajl (i kopira sadržaj segmenata) u trenutku kompajliranja i predstavlja objektni fajl koji može sadržati npr. statičku biblioteku.

- **Deljeni objektni fajl** (*shared object file*), ili deljena biblioteka sadrzi biblioteku za dinamicko linkovanje. Biblioteka je ulinkovana u postupku pravljenja izvršnog fajla i mora biti na sistemu za vreme izvršavanja aplikacije i u vreme kompajliranja.

- **Izvršni *image* fajl** (*executable image file*) predstavlja konačni proizvod kompajliranja izvornog koda, gde se izvorni kod prevodi u mašinski kod od strane kompajlera, a zatim povezuje sa neophodnim bibliotekama da bi se kreirala datoteka koja se može pokrenuti na operativnom sistemu.

**Kompajler** kreira tabelu simbola, koja sadrži mapiranje naziva simbola u adrese, što odgovara postupku rešavanja simbola. Prilikom kreiranja izlaza, kompajler kreira adrese za svaki simbol koje su relativne za fajl koji se kompajlira. Tabela simbola sadrži simbole definisane u fajlu koji se kompajlirao, kao i spoljne simbole (iz drugih fajlova) koji se pozivaju u fajlu i koje linker treba da razreši.

**Proces rešavanja simbola** (*Symbol Resolution*) podrazumeva prolaze linkera kroz svaki objektni fajl i pronalaženje za taj objektni fajl, fajl ili fajlove u kojima su spoljni simboli definisani i kreiranje odgovarajućih elemenata u tabeli simbola. U slučaju kada su spoljni simboli definisani u statičkoj biblioteci, linker kopira objektni kod iz biblioteke i smešta ga u konačni *image* fajl. Ovaj proces označava **proces statičkog linkovanja**.

**Realokacija simbola** (*Symbol Relocation*) je proces u kome linker mapira reference na simbole na njihovu definiciju. U ovom procesu linker modifikuje mašinski kod linkovanih objektnih fajlova tako da reference na simbole date u kodu odgovaraju stvarnim adresama dodeljenim datim simbolima. **Tabela realokacija** govori linkeru gde u programskom kodu da izvrši realokaciju.

Za kreiranje izvršnog *image* fajla, svi spoljni simboli moraju biti **razrešeni** kako bi svaki simbol imao definisanu memorijsku adresu u trenutku izvršavanja. 

> [!NOTE] 
> Izuzetak od ovog pravila je slučaj simbola definisanih u deljenim bibliotekama koji i dalje mogu imati relativne adrese, koje se rešavaju u trenutku izvršavanja ili učitavanja. Ovaj proces odgovara dinamičkom linkovanju.

Kod **dinamičkog linkovanja** imamo manji izvršni kod aplikacije, duže vreme učitavanja i znatno veći broj sistemskih poziva, tj. sporije izvršavanje aplikacije. U većini slučajeva, dinamičko linkovanje je dominantni način linkovanja, jer u slučaju promene biblioteke nije potrebno re-kompajliranje koda aplikacije.

**Relokabilni objektni fajl** takođe može imati nerešene spoljne simbole. Ovaj fajl se može koristiti za dalje linkovanje sa drugim objektnim fajlovima kako bi se kreirao izvršni *image* fajl ili kao deljeni objektni fajl.

**Deljeni objektni fajl** može se koristiti za linkovanje sa drugim deljenim objektnim fajlovima ili realokatibilni objektnim fajlovima, ili se može koristiti kao izvršni *image* fajl u procesu dinamičkog linkovanja kao dinamička biblioteka.

Dva uobičajena **formata objektnih fajlova** su COFF (*Common Object File Format*) i ELF (*Executable and Linking Format*). IDE alati različito interpretiraju ELF fajl format:

- *Linker* interpretira objektni ELF fajl kao linkabilni modul čiji je opis dat u tabeli zaglavlja sekcije (*section header table*).
- *Loader* interpretira izvršni ELF fajl kao izvršni modul čiji je opis dat u tabeli zaglavlja programa (*program header table*)

***Loader*** je program koji se nalazi u ROM memoriji, koji kopira inicijalizovane promenljive u RAM, prebacuje 
programski kod u RAM i inicira izvršavanje programa iz RAM memorije. 

> [!IMPORTANT]
> Linker koristi adresu izvršavanja programa u procesu rešavanja simbola.

Tipovi sekcija kod ELF formata definisani poljem `sh_type`:

| Tip       | Opis                                      |
| --------- | ----------------------------------------- |
| NULL      | Inactive header without a section.        |
| PROGBITS  | Code or initialized data.                 |
| SYMTAB    | Symbol table for static linking.          |
| STRTAB    | String table.                             |
| RELA/REL  | Relocation entries.                       |
| HASH      | Run-time symbol hash table.               |
| DYNAMIC   | Information used for dynamic linking.     |
| NOBITS    | Uninitialized data.                       |
| DYNSYM    | Symbol table for dynamic linking.         |

Atributi sekcije definisani preko polja `sh_flags`:

| Tip       | Opis                                      |
| --------- | ----------------------------------------- |
| WRITE     | Section contains writeable data.          |
| ALLOC     | Section contains allocated data.          |
| EXECINSTR | Section contains executable instructions. |

Osnovne sekcije:

- Programski kod i konstante su definisane u `.text` sekciji.

- Sekcije `.sbss` (*small bss*) i `.bss` sadrže neinicijalizovane podatke.

- Sekcije `.sdata` i `.data` sadrže inicijalizovane podatke, pri čemu `.sdata` (*small data*) sekcija sadrži podatke odgovarajuće veličine.

- Druge standardne sekcije definisane od strane sistema su `.symtab` koja sadrži tabelu simbola, `.strtab` koja sadrži tabelu stringova za programske simbole, `.shstrtab` koja sadrži tabelu stringova za nazive sekcija. 

> [!NOTE]
> Razvojni inženjer može definisati proizvoljnu sekciju pozivom komande linkera `.section naziv_sekcije`.

Sekcija `.text` sa izvršnim kodom ima `EXECINSTR` atribut. Ova sekcija je read-only, obzirom da se ne može očekivati da će se programski kôd i konstante menjati za vreme izvršavanja programa. Sekcije `.sdata` i `.data` imaju `WRITE` atribut. Sekcije `.sbss` i `.bss` imaju i `WRITE` i `ALLOC` atribute.


Polje `sh_addr` sadrži adresu gde će programska sekcija biti smeštena (učitana) na *target* sistemu (adresa učitavanja). Polje `p_paddr` sadrži adresu gde će programski segment biti u odredišnoj memoriji za izvršavanje (adresa izvršavanja).

> [!NOTE] 
> Kod mnogih namenskih aplikacija, adresa izvršavanja i adresa učitavanja su iste, što označava da se aplikacije direktno učitavaju u memoriju target sistema za neposredno izvršavanje.

Nakon što je više izvornih fajlova kompajlirano u ELF objektne fajlove, linker mora kombinovati ove objektne fajlove kako bi spojio sekcije iz različitih objektnih fajlova u programske segmente. Kao rezultat ovog procesa kreira se jedinstveni izvršni *image* fajl za namenski sistem. Razvojni inženjer koristi komande linkera (ili direktive linkera) kako bi kontrolisao proces kombinovanja sekcija i alokacije segmenata na namenskom sistemu. Ove direktive se nalaze u **komandnom fajlu linkera**.

Dve direktive su podržane od većine linkera:

`MEMORY` - direktiva se koristi za opis memorijske mape target sistema
`SECTION` -  direktiva linkeru naznačava koje ulazne sekcije treba da kombinuje u koji izlazni segment, koje izlazne sekcije treba da grupiše i gde da ih alocira

```
MEMORY {
    ROM: origin = 0x00000h, length = 0x000100h
    FLASH: origin = 0x00110h, length = 0x004000h
    RAMB0: origin = 0x05000h, length = 0x020000h
    RAMB1: origin = 0x25000h, length = 0x200000h
}
SECTION {
    .rodata : > ROM
    _loader : > FLASH
    _wflash : > FLASH
    _monitor : > RAMB0
    .sbss (ALIGN 4) : > RAMB0
    .sdata (ALIGN 4) : > RAMB0
    .text : > RAMB1
    .bss (ALIGN 4) : > RAMB1
    .data (ALIGN 4) : > RAMB1
}
```

### *Debugging*

**Debagovanje** namenskog sistema je veoma ograničeno obzirom na probleme uvida u interna stanja sistema u realnom okruženju.

- Softverske tehnike: logging, dumping, print i metode vizuelizacije (LED indikacije).
- Hardverske tehnike podrazumevaju hardversku podršku na strani target sistema koja je ugrađena u sistem/čip

**"PRINTF" *debugging*** - u slučaju kada se imamo ponašanje softvera koje je ne očekivano, dodaju se u kod dijagnostički pozivi funkcije printf koji prikazuju relevantne podatke na konzolu za vreme izvršavanja koda.

***Run-stop debug*** koristi kontrolu izvršavanja programa za pokretanje i prekidanje programskog toka u određenom trenutku ili na tačno određenoj poziciji programskog toka koja je definisana kao ***breakpoint***. Razvojni inženjer koristi *cross-debugger* na *host* strani, koji komunicira sa target CPU preko npr. JTAG konekcije.

***Stopping*** tehnika podrazumeva zaustavljanje taktnih signala što rezultuje u zamrzavanju stanja flip-flopova (registara) i memorijskih lokacija.

***Halting*** tehnika podrazumeva da se komponente sistema stavi u idle mod, zaustavljajući procesiranje.
- *Computation-centered debug* kontrolisan u formi prekida i servisne rutine koja omogućava prijem komandi za pristup stanjima sistema od strane spoljnog *debug* softvera.
- *Communication-centered debug* kroz koji se kontroliše sistem interkonekcije i prenos komandi i podataka.

- ***Joint Test Action Group*** (JTAG) i ***Background Debugging Mode*** (BDM) su metode za pristup memorijskim i CPU resursima na strani *target* sistema. *Host* debager se preko JTAG/BDM porta vezuje na *target* platformu bez zahteva da se na *target* sistemu izvršava posebna aplikacija.

**Softverski emulatori** (simulatori) su alati sposobni da simuliraju izvršavanje programskog koda na određenom CPU. Pomoću emulatora je moguće debagovati programski kod preko uvida u vrednosti registara CPU i registara integrisanih modula, bez posedovanja čipa.

***In-circuit* emulatori** su uređaji koji omogućavaju emulaciju rada CPU i postavljaju se na mesto CPU (preko socket-a) obzirom da imaju isti broj pinova kao originalni CPU. Drugi deo emulatora je povezan na standardni PC računar gde je pokrenut debager.

***Real-time trece debug*** tehnika podrazumeva pristup internim signalima unutar čipa čime se omogućava uvid u vremensko ponašanje sistema u dužem vremenskog intervalu. Uobičajeni signali koji su dostupni preko spoljašnjih pinova su signali takta, reset signali, kontrolni signali dozvole i potvrde operacija, kao i snimljena stanja promenljivih i registara. Obzirom na konačan broj spolja dostupnih signala (preko *high speed* interfejsa), koristi se multipleksiranje signala ili preuzimanje informacija o signalima u internim trace baferima koji su kasnije dostupni preko *low speed debug* interfejsa. Za vreme rada sistema, *trace module* beleži informacije o izvršavanju na strani *target* sistema u za to predviđenoj memoriji.

Razvojno okruženje je bazirano na *open-source* Eclipse IDE i GNU alatima (binutils, gcc, gdb). Izvorno Eclipse nije napravljen za *cross-development* ili za C/C++ programske jezike koji se najčešće koriste kod razvoja namenskog softvera. Takođe Eclipse ne podržava *remote debug* koncept. GNU alati su dostupni u source formatu i moraju se kreirati za konkretnu 
host i target platformu.

**GNU alati** -  *Free Software Foundation* nudi set alata (dostupnih u formi izvornog koda) koji omogućavaju razvoj i debagovanje namenskog softvera. Osnovni alati su:
- Alati za razvoj koda, uključujući alate za asembliranje, linkovanje i arhiviranje (binutils)
- C/C++ kompajler (GCC)
- Alati za prebacivanje i debagovanje namenskog softvera na target platformi (GDB)

> [!NOTE]
> Iako alati pružaju podršku za široku lepezu procesora i proizvoljnu kombinaciju host OS i hardvera, korisnik mora da konfiguriše i kreira alate, što može biti vremenski zahtevan i frustrirajući posao.

Eclipse okruženje nudi *editor*, *project manager* i *debugger* interfejs. Dodatno je potrebno integrisati:
- Podršku za C/C++ *cross-development* (CDT *plug-in*)
- *Assembler*, *compiler*, *linker* i druge alate (GNU alati)
- *Remote debugger connection* (Zylin *plug-ins*)

> [!NOTE]
> U slučaju JTAG/BDM veze mora se obezbediti metod za komunikaciju GDB sa target sistemom. (alat proizvođača interfejsnog hardvera).

Kod upotrebe GDB, postoje dve osnovne metode za povezivanje na target sistem prilikom debagovanja:
- Upotreba **gdbserver** uslužnog programa koji dolazi sa GNU debagerom. gdbserver se kompajlira za target platformu gde može pokrenuti program koji se debaguje i može komunicirati sa gdb programom na host strani preko TCP/IP protokola ili preko serijske veze.
    - gdbserver 192.168.1.3:2000 /tmp/sum (target strana)
    - (gdb) target remote 192.168.1.10:2000 (host strana)
- **Stubs** su softverske rutine koje se mogu ulinkovati sa programom koji se debaguje i koje se koriste za povezivanje sa GNU debagerom sa strane target sistema, čime se eliminiše potreba za gdbserver programom.

> [!NOTE] 
> Korišćenje gdbserver metode je isto za sve platforme, dok se stub metoda razlikuje od platforme do platforme


## Inicijalizacija namenskog softvera

Izvršni image fajl pripremljen za *target* sistem je moguće prebaciti sa *host* razvojnog sistema na više načina. Ovaj postupak se u opštem slučaju naziva **učitavanje binarnog image**-a i može biti sproveden na sledeći način:

- Programiranjem celokupnog image fajla na EEPROM ili fleš memoriju.

- Spuštanjem image fajla preko serijske (RS-232) ili mrežne veze. Ovaj proces zahteva uslužni program za prenos podataka na *host* sistemu, kao i prisustvo *loader*, *monitor* ili *debug agent* programa na *target* sistemu.

- Spuštanje image fajla preko JTAG (Joint Test Action Group) ili BDM (Background Debug Mode) interfejsa.

Postupak *boot*-ovanja sistema sastoji se u **startovanja inicijalizacione rutine** (*boot code*) nakon uključenja napajanja.  Ova rutina je uobičajeno programirana u ROM kodu i ona inicijalizuje hardver *target* sistema, memoriju, PLL, spremajući sistem za startovanje *loader* programa.

***Loader* program učitava *image* fajl** direktno u RAM ili fleš memoriju *target* sistema, npr. preko mreže uz pomoć protokola kao što su TFTP ili FTP protokol. 

> [!NOTE]
> *Loader* treba da podržava format objektnog fajla (npr. ELF fajl format), kako bi prema definisanim adresama za učitavanje smestio odgovarajuće sekcije koda. 

Nakon prenosa podataka, **loader prebacuje kontrolu snimljenom *image* fajlu**. Ukoliko loader ima podršku za snimanje u fleš memoriju, loader može učitati *image* fajl u fleš memoriju.

Alternativni način za snimanje i pokretanje aplikacije pisane za namenski sistem je **upotreba *monitor* programa**. Uobičajeno *monitor* program predstavlja aplikaciju koju razvija proizvođač *target* sistema za razvojne ploče. Slično kao i inicijalizaciona rutina, monitor se startuje prilikom uključenja napajanja i obavlja sledeće inicijalizacione korake:

- Inicijalizacija potrebnih periferijskih uređaja, npr. serijskog interfejsa, tajmera...
- Inicijalizacija memorije sistema za snimanje *image*-a.
- Inicijalizacija prekidnog kontrolera i postavljanje osnovnih prekidnih rutina.

Pomoću definisanog seta komandi, monitor program omogućava korisniku da snimi *image* fajl, vrši postavljanje i čitanje lokacija u sistemskoj memoriji, vrši upis i čitanje sistemskih registara, postavlja i briše različite tipove breakpoint-a, izvršava program instrukciju po instrukciju, resetuje *target* sistem

Dakle, *monitor* program uključuje funkcionalnosti inicijalizacione rutine (*boot image*) i loader-a, zajedno sa pridodatim funkcionalnostima za debagovanje aplikacije.

**Funkcije *target debug agent*-a** su slične funkcijama *monitor* programa, sa dodatkom preko koga *target agent* pruža *host* debageru dovoljno informacija za vizuelno debagovanje izvornog koda.

Namenski procesori, nakon uključenja napajanja, preuzimaju i izvršavaju kod sa predefinisane adrese. Kod koji se nalazi na pomenutoj adresi se naziva **reset vektor**. Uobičajeno reset vektor predstavlja instrukciju skoka na drugi deo memorijskog prostora gde se nalazi inicijalizacioni kod ili sadrži adresu početka inicijalizacionog koda.

> [!NOTE]
> Reset vektor i inicijalizacioni kod, provera zaštite softvera i hardvera (*bootstrap* kod) su uobičajeno smešteni u neki vid ROM memorije.

1. Prvi deo postupka početne inicijalizacije sistema u poznato stanje uključuje postavljanje vrednosti registara procesora, inicijalizaciju steka, onemogućavanje sistemskih prekida, inicijalizaciju RAM memorije i keš memorije procesora. Obzirom da je izvršavanje koda brže iz RAM memorije nego njegovo izvršavanja iz fleš memorije, *loader* može kopirati kod iz fleš memorije u RAM. Omogućavanje debagovanja u toku izvršavanja programa je jedan od razloga za izvršavanje programa iz RAM-a, obzirom na neophodnost modifikacije koda kako bi bilo podržano postavljanje *breakpoint*-a.

2. Inicijalizovane sekcije sa podacima (`.data` i `.sdata`) sadrže inicijalne vrednosti globalnih i statičkih promenljivih, tako da je sadržaj ovih sekcija deo izvršnog *image* fajla i prema tome, u originalnom izgledu se kopira u RAM memoriju od strane *loader* programa. Sa druge strane, sadržaj neinicijalizovanih sekcija sa podacima (`.bss` i `.sbss`) je prazan. *Linker* rezerviše prostor za ove sekcije u memorijskoj mapi sistema.  Konstante koje se nalaze u `.const` sekciji je moguće ostaviti u *read only* memoriji tokom izvršavanja programa. *Lookup* tabele, ili druge konstante kojima se često pristupa je potrebno smestiti u RAM memoriju.

3. Inicijalizacija uređaja sistema od strane *loader* programa. U ovom koraku se inicijalizuju samo uređaji neophodni od strane *loader*-a i to samo neke od njihovih funkcionalnosti. Uobičajeno je da su ti uređaji deo I/O sistema. Nakon inicijalizacije *loader* je spreman za prebacivanje *image* fajla aplikacije, koji se sastoji od RTOS-a, i koda aplikacije, na *target* 
sistem.

> [!NOTE]
> *Image* fajl aplikacije u opštem slučaju može biti u nekom od memorijskih uređaja na *target* sistemu ili *host* razvojnom sistemu.

**Izvršavanje koda iz ROM memorije**:

Programski segmenti sadrže binarni mašinski kod spreman za izvršavanje, tj. *boot image* se kreira u ELF formatu, međutim, softver za programiranje EEPROM-a, uklanja podatke specifične za format ELF fajla, kao što su tabele zaglavlja programa i sekcije, prilikom programiranja *boot image* fajla u ROM. Sekcija `.data` je u celosti kopirana u RAM, tako da *boot image* 
mora znati adresu početka sekcije sa podacima i njenu veličinu. Jedan način je da se u `.data` sekciji uz pomoć specijalnih labela markiraju adrese početka i kraja sekcije. Ovo se može postići i preko direktiva asemblera (`ORG` direktiva).

**Izvršavanje koda iz RAM memorije I**:

Uobičajeno je da veliki *image* fajl aplikacije bude smešten u ROM-u u komprimovanoj formi, tako da *loader* program mora najpre da izvrši njegovu dekompresiju, pre inicijalizacije sekcija *image* fajla. Preporučljivo je da se nakon dekompresije izvrše izračunavanja kontrolne sume *boot image*-a kako bi se proverio integritet fajla pre njegovog snimanja i započinjanja izvršavanja.

**Izvršavanje koda iz RAM memorije II**:

Kod ovog scenarija *boot*-ovanja, *target debug agent* prebacuje *image* fajl aplikacije sa *host* sistema u RAM na *target* sistemu za njeno izvršavanje. Ovaj postupak je uobičajen za kasniju fazu razvoja aplikacije, kada je većina drajvera uređaja u potpunosti implementirana i testirana. U ovom slučaju podrazumeva se korektno procesiranje prekida i izuzetaka od strane sistema. Razvojni inženjer pristupa komandnom interfejsu *debug agenta* preko terminal programa preko serijske veze. Zadavajući komande, on može dati instrukcije *debug agentu* vezane za lokaciju *image* fajla na *target* sistemu i inicijalizovati transfer fajla.

***Target image*** koji je često pominjan u prethodnom tekstu predstavlja kombinaciju sofisticiranih komponenta i modula softvera. Ove komponente softvera, pored koda aplikacije, uključuju BSP, koji uključuje široku lepezu drajvera za hardverske komponente sistema i uređaje. 

**RTOS** obezbeđuje osnovne servise za *real-time* izvršavanje, kao što su servisi za sinhronizaciju resursa, I/O servise, servis za raspoređivanje izvršavanja *task*-ova na sistemu, kao i druge servise kao što su *file system* i mrežni servis.

Nakon početne inicijalizacije (procesa *boot*-ovanja) sistema, preostali glavni koraci do potpune inicijalizacije sistema su:
- Inicijalizacija hardvera sistema
- Inicijalizacija RTOS
- Inicijalizacija aplikacije

Proces **inicijalizacije hardvera** sistema započinje nakon izvršavanja instrukcije iz reset vektora. Tipično u ovoj fazi vrši se minimalna inicijalizacija komponenti hardvera (sadržanih u BSP) kako bi bilo omogućeno izvršavanje *boot image* fajla.
- Započinjanje izvršavanja od reset vektora.
- Postavljanje procesora u poznato stanje preko inicijalizacije potrebnih registara (postavljanje takta CPU).
- Onemogućavanje prekida i keširanja.
- Inicijalizacija kontrolera memorije, memorijskih čipova i jedinice za keširanje (preuzimanje početne adrese memorije, veličine memorije, izvršavanje preliminarnih memorijskih testova, ukoliko su zahtevani).

**Inicijalizacija RTOS-a** obuhvata inicijalizaciju različitih objekata i servisa RTOS, uobičajeno, prema sadržaju konfiguracionog fajla. Ovaj korak uključuje inicijalizaciju potrebnih *task*, semafor i sličnih objekata, tajmer servisa, servisa za rad sa izuzecima i za upravljanje memorijom. Kreiranje potrebnog steka za RTOS. Inicijalizacija dodataka RTOS-a, kao što su TCP/IP stek, fajl sistema... Startovanje RTOS i inicijalnih taskova.

Nakon što je RTOS inicijalizovan, kontrola izvršavanja se prebacuje korisničkoj aplikaciji preko poziva predefinisane funkcije. Nakon startovanja, **korisnička aplikacija** takođe prolazi kroz **proces inicijalizacije** potrebnih objekata, servisa, struktura podataka, promenljivih, itd.

## Upravljanje memorijom

Prvobitni koncept je da su memorijski resursi mapirani kao deo adresne mape, tj. u **fizičkom adresnom prostoru**. Iz programskog koda se direktno pristupa fizičkim memorijskim lokacijama koje pripadaju određenim segmentima u memoriji, na *heap*-u ili na *stack*-u.

Kod naprednijeg koncepta pristup memoriji se vrši kroz **virtuelno adresiranje**. Adresni prostor preko koga se pristupa segmentu memorije dat je u formi virtuelnih adresa koje se ne poklapaju sa fizičkim adresnim prostorom. U slučaju zahteva za pristupom memorijskoj adresi, adresa se translira u fizičku adresu u memoriji.

> [!IMPORTANT]
> Jednostavniji namenski sistemi, koji zahtevaju brzo i vremenski striktno ograničeno vreme odziva u manjoj meri koriste tehniku virtuelne memorije.

Hardverska podrška za rad sa virtuelnim adresama je data u formi **MMU** (***Memory Management Unit***) jedinice. MMU predstavlja hardversku komponentu koja je odgovorna za procesiranje zahteva za pristup memoriji od strane CPU. MMU vrši preslikavanje virtuelnih u fizičke adrese, zaštitu pristupa, kontrolu keširanja, arbitraciju pristupa magistrali...

MMU vrši mapiranje delova virtuelnog memorijskog prostora koji je organizovan u blokove (*pages* veličine kB), u fizičke adrese, preko TLB-a (*Translation Look-aside Buffer*) ili preko tabele stranica (*translation table* ili *page table*).

> [!NOTE]
> TLB je deo MMU, dok je tabela stranica u RAM-u.

**Tabela stranica** je struktura podataka gde OS drži `virtuelna adresa -> fizička adresa` mapiranja, pri čemu svako mapiranje predstavlja jedan ulaz u tabeli (PTE – *page table entry*). Svaki proces ima svoju tabelu stranica koju referencira preko pokazivača na početak tabele stranica. Ako ne postoji traženi ulaz (VA) u tabeli stranica (*miss*) ili je zahtev pogrešan (generiše se npr. signal *segmentation fault* – *memory access violation*) ili tražena stranica trenutno nije u fizičkoj memoriji (*page fault*) već je u nekoj memoriji višeg hijerarhijskog nivoa (npr. na HDD). Kao akcija u tom slučaju potrebno je da se stranica prebaci u fizički adresibilnu memoriju i kreira validan PTE.

**TLB** (***Translation Look-aside Buffer***) sadrži keširane ulaze iz tabele stranica dostupne u okviru MMU. Informacije koje se nalaze u okviru TLB-a sadrže i podatak o tome da li je stranica menjana, kada je poslednje pristupano stranici (npr. za implementaciju LRU - *least recently used* algoritma zamene stranica u TLB), koji tip procesa je pristupao stranici (*user mode*, *supervisor mode*).

**Virtuelno adresiranje**:

1. Kada VA treba da se translira u PA, najpre se pretražuje TLB.

2. Ukoliko je mapiranje u TLB (*valid entry*) imamo `TLB_hit`, formira se PA.

3. U slučaju `TLB_miss`, pretražuje se *page table* da se vidi da li mapiranje postoji.

4. U slučaju `page_hit`, ulaz se upisuje u TLB nakon čega se formira PA.

5. U slučaju `page_miss` imamo `page_fault` (*segmentation fault*), tj. ili je VA pogrešna ili stranica nije u dostupnom prostoru fizičkih adresa (RAM), već na npr. disku. Ako je stranica na disku, potrebno ju je dovući u RAM i ažurirati ulaz u page table i TLB, nakon čega se dobija PA.

U slučaju ako nema slobodne RAM memorije, koristi se algoritam zamene stranica u tabeli stranica, pri čemu se zamenjena stranica snima na disk, a novoj stranici se dodeljuje prostor u RAM memoriji (*paging process*).

### Alokacija memorije

U slučaju **statičke alokacije**, memorija se rezerviše još u procesu kompajliranja i linkovanja. Sve globalne promenljive, bez obzira da li su deklarisane kao statičke (`static`) i sve statičke lokalne promenljive se statički alociraju. Sve statički alocirane promenljive poseduju memoriju koja je alocirana i inicijalizovana pre pokretanja aplikacije i ove memorijske lokacije se ne oslobađaju sve dok se ne završi izvršavanje aplikacije.

Dostupnost (*scope*) i definisanost:
- Lokalne statičke (`static` - dostupna i definisana u bloku)
- Globalne statičke (`static` – def. van bloka, dostupna u okviru fajla)
- Globalne (*global* – def. kao globalna, dostupna iz svih fajlova kroz deklaraciju `extern`)

Promenljive deklarisane u bloku koda su po definiciji automatske promenljive. Prilikom započinjanja izvršavanja koda koji je sadržan u bloku, automatske promenljive se **automatski alociraju** na **steku**, dok se prilikom napuštanja izvršavanja bloka promenljive dealociraju. Termin lokalne promenljive je uobičajeno sinonim za automatske promenljive.

Nakon završetka inicijalizacije sistema programski kod, podaci i stek sistema zauzimaju deo fizičke memorije sistema. Takođe, deo memorije se koristi od strane RTOS za namene **dinamičke alokacije memorije**. Ova memorija se naziva ***heap***.

Postojanje izolovanih slobodnih blokova se podvlači pod pojam **spoljne fragmentacije**, obzirom da fragmentacija postoji u okviru tabele alokacije. Način da se eliminiše ovaj tip 
fragmentacije je **komprimovanje** (*compact*) izolovanih slobodnih blokova.

> [!WARNING]
Proces komprimovanja se skoro nikada **ne obavlja** kod namenskih sistema zbog vremenske zahtevnosti procesa kopiranja sadržaja memorije sa jedne na drugu lokaciju. Proces komprimovanja memorije je dozvoljen ukoliko *task*-ovi koji poseduju memorijske blokove, pristupaju blokovima, uz pomoć virtuelnih adresa. Kod namenskih sistema je proces komprimovanja memorije vezan striktno za spajanje više susednih slobodnih memorijskih blokova u veći slobodan blok memorije za namene dinamičke alokacije.

Proces upravljanja memorijom kod nekih arhitektura ograničen različitim restrikcijama u pogledu zahteva za **poravnanjem memorije** (*memory alignment*), koji se odnosi na adresu podatka u memoriji. Zato mnogi namenski procesori ne mogu pristupiti više bajtnom podatku sa bilo koje adrese, u protivnom pristup memoriji rezultira u grešci na magistrali i dovodi do generisanja izuzetka.

## Veza hardvera i softvera namenskog sistema

Razlikujemo tri vremenska domena
- vreme unosa programskog koda (*code time*)
- vreme kompajliranja/kreiranja izvršnih fajlova (*compile time*)
- vreme izvršavanja programskog koda (*run time*)

**ISA** (***Instruction Set Architecture***) definiše:
- Stanje sistema (tj. registre, pristup memoriji)
- Set instrukcija koje CPU može izvršiti (kodovanje operacija, adresne modove)
- Interakciju izvršavanja svake instrukcije sa stanjem sistema
- Upotreba viših programskih jezika

Tok kontrole izvršavanja programa ili **programski tok** je određen sekvencom izvršavanja instrukcija.

Radnje koje se obavljaju prilikom poziva procedure definišu gde se nalaze/smeštaju određene informacije (***calling convention***). Iako tačni koraci variraju od sistema do sistema moguće je identifikovati sledeće zajedničke korake:

-  Pozvana rutina (*callee*) mora znati gde da nađe argumente funkcijskog poziva (*args*) i mora znati gde da nađe adresu povratka iz funkcijskog poziva (*return address*).

- Rutina pozivaoca (*caller*) mora da zna gde da nađe povratnu vrednost funkcije (*return value*).

- Obe rutine se izvršavaju na istom CPU, dakle koriste iste registre, pa i oni moraju da se pamte kao deo zamene konteksta.

**Argumenti funkcijskog poziva** se mogu prosleđivati preko steka, preko posebnih registara ili kombinovano.

**Povratna vrednost** funkcijskog poziva se prosleđuje preko posebnog registra u koji upis vrši pozvana rutina. Veličina registra je ograničena pa je za povratni podatak dužeg zapisa preporučljivo vratiti pokazivač na podatak.

Svi registri CPU koji se koriste prema proceduri izvršavanja funkcijskog poziva se moraju zapamtiti od strane pozivaoca kao **kontekst pozivaoca**. Snimanje registara može biti prema *callee-save* ili *caller-save* konvenciji.

**Adresa povratka** iz funkcijskog poziva se upisuje od strane `call` instrukcije.

**Memorija** je organizovana kao jedinstven niz bajtova, gde svaki od njih ima jedinstvenu adresu i može biti pročitan ili upisan. Skup dostupnih adresa u memoriji predstavlja **adresni prostor**. Jedinstveni podatak ne može uvek biti smešten na jednu adresu, tj. većina 
operacija koristi višebajtne vrednosti. **Pokazivač** je promenljiva (data object) koji sadrži adresu (lokaciju u memoriji), pri čemu adresa može pokazivati na bilo koji podatak. Osnovna višebajtna vrednost je definisana kao **mašinska reč** koja je ograničena sa veličinom adresnog prostora, veličinom memorije i širinom registara.

**Adrese** specificiraju lokaciju grupe bajtova u memoriji. Adresa reči je jednaka adresi prvog bajta reči. Pozicija bajtova u rečima je bitna u slučaju kada se pristupa drugačijoj količini podataka u odnosu na onu koja se upisuje.

- ***Big-endian*** (SPARC, z/Architecture) - najmanje značajni bajt je na najvišoj adresi

- ***Little-endian*** (x86, x86-64) - najmanje značajni bajt je na najnižoj adresi

- ***Bi-endian*** (ARM, PowerPC) -  specificira se ili *Little* ili *Big endian*

## UML modeliranje softvera

UML se koristi za prikaz modela iz dva različita ugla:

- **Statički ili strukturalni prikaz** -  Naglašava se statička struktura softvera/sistema uz pomoć objekata, atributa, operacija i relacija.

- **Dinamički prikaz ili ponašanje** - Prikazuje se kolaboracija između objekata i promene njihovih stanja u formi dijagrama sekvence, aktivnosti ili mašine stanja.

UML 2.0 definiše 13+ osnovnih tipova dijagrama podeljenih u dve kategorije:

- **Modeliranje strukture softvera** - Dijagrami definišu statički prikaz softvera, modelirajući sastavne elemente – klase, objekte, interfejse, fizičke komponente softvera. Takođe ovi dijagrami definišu i relacije i zavisnosti između elemenata.

    - **Dijagrami pakovanja** (*package diagrams*) koriste za dekompoziciju modela na high-level elemente opisujući interakciju između njih.
  
    - **Klasni ili strukturni dijagrami** definišu osnovne gradivne blokove modela – tipove, klase...
    
    - **Objektni dijagram** opisuje kako se instance strukturnih elemenata međusobno odnose i koriste u realnom radu.
    
    - **Komponentni dijagrami** se koriste za modeliranje kompleksnih struktura (i njihovih interfejsa) sačinjenih od kolekcije strukturnih elemenata, klasa. 
    
    - **Dijagrami razmeštanja** (*deployment diagrams*) prikazuju fizičku dekompoziciju bitnih elemenata u realnom okruženju.
    
    - **Kompozitni dijagrami** daju strukturne elemente fokusirajući se na njihove unutrašnje detalje.

- **Modeliranje ponašanja sistema** - Dijagrami opisuju raznovrsne oblike interakcije i trenutna stanja unutar modela prilikom izvršavanja softvera tokom vremena.

    - **Studije slučaja** (*use case diagrams*) opisuju interakciju korisnik-sistem. Dijagrami definišu ponašanje, funkcionalne zahteve i ograničenja sistema kroz primere.
    
    - **Dijagrami aktivnosti** imaju višestruku upotrebu od definisanja programskog toka, akcija i grananja...
    
    - **Mašine stanja** prikazuje radna stanja participanata.
    
    - **Dijagrami komunikacije** opisuju sekvencu poruka koje se razmenjuju između objekata tokom izvršavanja
    
    - **Dijagrami sekvence** su bliski komunikacionim dijagramima opisujući stanja objekata tokom vremena i poruke koje modifikuju stanja objekata.
    
    - **Dijagrami interakcije** komprimuju informacije iz dijagrama aktivnosti i sekvence kako bi istakli vezu sa programskim tokom.

### Dijagram aktivnosti

**Dijagrami aktivnosti** se koriste da bi opisali sekvencu akcija (aktivnost) od početka do kraja aktivnosti. Dijagram je dat u formi sekvence akcija prilikom progresa aktivnosti. Dijagram opisuje dinamičko ponašanje sistema ili tok progresa aktivnosti. Dijagram aktivnosti (ili dijagram toka) se koristi i za opis segmenata sa paralelizovanim/konkurentnim procesiranjem.

**Aktivnost** podrazumeva skup akcija, njihovu sinhronizaciju ili tok njihovog izvršavanja i ostale elemente (nodove i sl.) koji se koriste za definisanje aktivnosti.

**Akcija** je imenovani element koji reprezentuje jedan atomični ili definisani korak unutar aktivnosti. Akcija se predstavlja u formi pravougaonika za zaobljenim ivicama.

**Tok kontrole** (*control flow* ili *activity flow*) predstavlja putanju koja definiše tranziciju od jedne do druge aktivnosti. Svaka aktivnost može imati više dolaznih ili odlaznih tokova aktivnosti.

**Objektni tok** podrazumeva akcije koja koriste instancu objekta kao ulaz (strelica od objekta ka akciji) ili izlaz, (strelica ka objektu) i nad kojim se obavlja aktivnost.

**Inicijalni** ili **početni nod** predstavlja ulaznu tačku aktivnosti.

Postoje dve vrste krajnjih nodova. **Krajnji nod aktivnosti** podrazumeva krajnji nod svih kontrolnih tokova koji su sadržani u okviru aktivnosti. **Krajnji nod toka** kontrole (toka procesiranja ili izvršavanja) podrazumeva krajnji nod samo konkretnog kontrolnog toka.

**Pin** je objektni nod koji obezbeđuje ulaze i izlaze za akcije. Predstavlja se u kvadratnom obliku sa nazivom podatka.

**Putanje** mogu imati **uslov** za realizaciju. Uslov se ispituje kod svakog potencijalnog prolaza datom putanjom. Navodi se u formi logičkog uslova u ugaonoj zagradi. Ispunjen uslov podrazumeva prolaz putanjom.

**Konektori** se koriste za izbegavanje crtanja dugačkih putanja. Podrazumevana putanja spaja ulaznu u izlaznu strelicu.

Uz pomoć ***weight*** definiše se vrednost za koju se prelaz realizuje.

U slučaju kada treba odlučiti o daljem toku kontrole, koristi se **nod odlučivanja/račvanja **(*decision node*) koji ima jednu dolaznu putanju i jednu ili više odlaznih putanja/strelica. Odlučivanje o odlaznoj putanji zavisi od evaluacije uslova (*guards*) specificiranih u uglastim zagradama.

</div>
