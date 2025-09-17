# DVS Predavanja

## Projektovanje složenih IK i sistema

Razvoj tehnologije je omogućio da se kompleksni digitalni sistemi mogu projektovati na jednom čipu (***System on Chip*** - SoC).

RTL projektovanje je prevaziđeno na nivou sistema. 

Nivo ponašanja sistema:
- Opisuju se blokovi i njihovi interfejsi
- Može biti uključeno vreme
- Može se simulirati
 
Funkcionalni nivo:
- Opisuju se algoritmi, specifikacije sistema
- Nema vremenskih parametara
- Može se simulirati

KlasifikacijaIP blokova:
- Soft IP (RTL):
    - High flexibility/low predictability
    - Synthesize from hardware description language (HDL)
- Firm IP (gate level):
    - Medium flexibility/medium predictability
    - Gate level netlist that is ready for P&R
- Hard IP (layout level):
    - Low flexibility/high predictability
    - Layout and technology dependent information

***System in Package*** (SiP) tehnologija - karakteriše je realizacija u jednom kućištu bilo koje kombinacije aktivnih, pasivnih, optičkih, memorijskih i drugih komponenata koje čine neki električni sistem ili deo sistema. Prednost SiP tehnologije je značajno redukovanje veličine, vremena proizvodnje i cene sistema.

Tipovi realizacije SiP-a:
- Side by Side Placement
- Stacked Structure
- Embedded Structure

***Stacked Silicon Interconnect*** (SSI) je tehnologija za pravljenje čipova gde se koristi silikonski uložak (*interposer*) između osnove u kojoj je napravljena logika i supstrata pakovanja čipa. Prevaziđena ograničenja Murovog zakona, dobijen veliki logički kapacitet i propusni opseg. Omogućena je brza fabrikacija složenih sistema na čipu.


## System C

C++ ne podržava:
- konkurentnost (HW u principu uvek radi paralelno)
- vreme kao parametar (modelovanje takta, kašnjenja)
- koncept signala koji predstavlja osnovu za komunikaciju u hardveru
- neke važne tipove promenljivih (logičke vrednosti, bit vektori, fix point matematika)

**System C** predstavlja skup definicija C++ klasa, kao i metodologija za njihovu upotrebu u modelovanju složenih elektronskih sistema, bilo na sistemskom nivou, bilo na nivou jezika za opis hardvera. Jedinstven objektno-orijentisan jezik za modelovanje i hardvera i softvera kod koga je uveden koncept signala u softver.  System C nije još jedan HDL, već biblioteka C++ klasa koje uvode vremenske parametre za prenos signala.

Modelovanje sistema u System C-u:
- Funkcionalni algoritamski model - analiziraju se performanse specificiranog sistema, istražuje se pogodna HW/SW arhitektura i proveravaju algoritmi

- Model prelaza (**Transaction Level Model** - TLM)
    - opis hardvera na nivou prenosa podataka kroz sistem (iznad RTL)
    - samo za HW komponente
    - interfejsi između blokova se modeluju kanalima, ne daju detalje o pinovima 
    - model pokreću događaji, a ne signal takta (zbog čega je brža simulacija u odnosu na RTL model)

- RTL model
   - detaljno opisan sistem, svaki registar, magistrala ili bit opisani su za svaki ciklus takta
   - na ovom nivou se može preći na HDL opis, ali se može i ostati u System C-u zbog verifikacije (*testbench*)
   - može se sintetisati pod uslovom da su poštovana određena pravila pri pisanju koda

SystemC model se sastoji od skupa **modula** koji služe za opis strukture. U okviru modula se mogu instancirati drugi moduli, što je pogodno za opis hijerarhije. Komunikacija sa modulom se obavlja preko **portova**. Moduli sadrže **procese** koji opisuju funkcionalnost sistema (konkurentni su međusobno). Za komunikaciju između modula i procesa se koriste interfejsi i kanali. **Interfejs** definiše skup metoda koje kanal obezbeđuje, ali ne daje njihovu implementaciju. Implementacija interfejsa se ostvaruje u **kanalu**. Kanal može implementirati više interfejsa.

Sinhronizacija u SystemC modelu se u osnovi bazira na događajima (*events*). Svi tipovi podataka iz C++ jezika se mogu koristiti, osim kod modela koji će se kasnije implementirati u hardveru pošto alati uglavnom ne podržavaju sintezu podataka tipa float i double, kao ni pokazivač na podatke bilo kog tipa.

Svaki proces osetljiv na promenu signala definisanog u listi osetljivosti će izvršiti deo koda pre nego što dobrovoljno vrati kontrolu simulatoru.


## Tehnike redukovanja potrošnje u SoC-u

Potrošnja:

- **Statička** potrošnja je proizvod napona napajanja i jednosmerne struje u kolu
  - uglavnom potiče od struje curenja  kroz supstrat i ima sve veći udeo u ukupnoj potrošnji
  - u nekim blokovima se koriste nMOS ili pseudo nMOS logika

- **Dinamička** potrošnja se sastoji od:
  - potrošnje u prelaznom režimu usled struja kroz tranzistore koji menjaju logičko stanje
  - potrošnje izazvane punjenjem i pražnjenjem kapacitivnih opterećenja

**Skaliranje Vdd** - Zavisnost dinamičke potrošnje od napona napajanja je kvadratna, a 
statičke linearna, pa smanjivanje Vdd deluje kao najefikasniji metod. Snižavanjem napona 
napajanja se degradiraju karakteristike tranzistora i povećava se kašnjenje.

**Energy-Delay Product** (EDP) faktor treba koristiti za procenu u sistemima gde je podjednako 
važno smanjiti utrošenu energiju i kašnjenje.

Ukupnu potrošnju sistema treba smanjiti na račun disipacije ili smanjivanjem ukupne aktivnosti kola, a da performanse budu očuvane ili bolje. Osnovne tehnike se svode na: 
- redukovati napon napajanja gde je moguće
- smanjiti kapacitivnosti
- minimizirati srednju učestanost promene signala u kolu

**Common Power Format** (CPF) je nova metodologija projektovanja SoC male potrošnje koju uvodi *Low-Power Coalition*. Za svaku od navedenih tehnika se definiše njen uticaj na dinamičku potrošnju, struje curenja, površinu, kompleksnost...

### Tehnike u domenu tehnologije

Tehnološki postupci za **male napone napajanja**:
- CMOS postupak sa napajanjem od 200mV (kola osetljiva na šum)

Tehnološki postupci sa **smanjenim kapacitivnostima**:
- Uvođenje bakarnih veza (Motorola, IBM)
- Dodavanje više slojeva veza, jer gornji slojevi imaju manje kapacitivnosti i pogodni su za razvođenje kritičnih signala
- Fabrikacija Si integrisanih kola na izolatorima - SOI tehnologije (manje kapacitivnosti spojeva)

> [!NOTE]
> Razvoj novih tehnoloških postupaka je veoma skup, pa ove tehnike nisu uvek isplative.

### Tehnike na nivou lejauta

Ove tehnike se svode na smanjivanje kapacitivnosti. Globalnim planiranjem lejauta i grupisanjem logičkih celina minimizira se dužina linija i parazitne kapacitivnosti veza. 

Kritični signali se izvode u sloju sa najmanjom kapacitivnošću. U okviru ćelije se projektuju tranzistori minimalnih dimenzija čime se smanjuju kapacitivna opterećenja, pa se pored manje potrošnje postiže i brži rad kola.

### Tehnike na logičkom nivou

Pored smanjivanja kapacitivnosti, ove tehnike su bazirane i na smanjivanju prosečne učestanosti signala. Prvi korak je izbor biblioteke sa logičkim kolima:

- ASIC (Standard cell) u principu daje bolje rezultate od programabilnih IK (npr. FPGA), jer su ćelije jednostavnije i imaju manje ulazne kapacitivnosti.
- Postoje posebne *low power* biblioteke za ASIC.

Kontrola trajanja uzlaznih i silaznih ivica signala, teži se smanjivanju tih vremena. Razvijene su posebne familije logičkih kola (npr. domino CMOS logika, kojom se dobija velika ušteda u odnosu na statički CMOS).

**Limited swing** tehnika se ostvaruje ograničavanjem promene pojedinih signala. Treba voditi računa da prepoznavanje logičkih nivoa bude moguće. Obično se moraju ubacivati pojačavači na određenim mestima, mada postoje modifikovana kola i bez pojačavača.

**Smanjivanje prosečne učestanosti signala**:
- Projektovanje dodatnih kola za blokadu nepotrebnih tranzicija signala (npr. ubacivanje signala dozvole).
- Prevencija pojave gličeva, čime se smanjuje srednja učestanost signala.

**Izolovanje operanada** - Ubacuje se signal 'dozvole' kojim se mogu izolovati operandi.

**Podešavanje VTh**:
- Korišćenje tranzistora sa različitim naponom praga.
  - Veći napon praga – manja brzina i struja curenja
  - Niži napon praga na kritičnim putanjama
  - Tehnika se primenjuje po ćelijama

- Potpražni režim rada MOS tranzistora.

- Dinamička promena napona praga tranzistora.
  - Kontrola preko substrata (Substrate Bias)
  - Što manji napon praga kada nam je brzina važna
  - Što veći napon praga u neaktivnom stanju
  - Smanjenje potrošnje korišćenjem velikih SLEEP tranzistora

### Tehnike na nivou arhitekture

Tehnike na nivou arhitekture su uglavnom bazirane na smanjivanju prosečne učestanosti signala.

**Clock gating** je tehnika selektivnog propuštanja takta. Takt se propušta samo ukoliko je kontrolni signal na aktivnom nivou (primenjuje se lokalno).

**Paralelovanje** je efikasan metod gde se smanji se napon napajanja, dodaju redundantni blokovi u kojima se višestruko obrađuju isti signali i poređenjem rezultata se rekonstruišu oštećene informacije. Koristi se *self-checking* hardver.

**Pipeline** - Ukoliko se paralelovanje kombinuje sa pipeline tehnikom postiže se još  manja potrošnja, ali je zauzeta površina silicijuma veća.

Korišćenje **više različitih napona napajanja** unutar jednog bloka. Samo neke putanje u bloku su kritične, kod ostalih možemo smanjivati napon napajanja. Konverzija nivoa se vrši pomoću flip-flopova.

### Tehnike na nivou sistema

**Multi-supply voltage design** - Korišćenje više napona napajanja za različite blokove:
- Poseban napon napajanja za ulazno-izlazne delove
- Logičko jezgro se napaja nižim naponom
- Potrebni konvertori nivoa

**DVFS** (Dynamic Voltage and Frequency Scaling) - Dinamička promena napona napajanja i frekvencije: 
- Promene napona napajanja i frekvencije u toku rada (često se koristi kod mikroprocesora opšte namene).
-  Postavlja se minimalan napon napajanja koji je neophodan za obavljanje određene operacije na željenoj frekvenciji. Promena napona napajanja u fiksnim diskretnim koracima (sistem je u otvorenoj sprezi).
-  Veoma efikasna tehnika, jer smanjuje i dinamičku i statičku potrošnju.

**AVFS** (Adaptive voltage and frequency scaling) - varijanta prethodne tehnike, ali je sistem u zatvorenoj povratnoj sprezi. Preciznija kontrola, ali mnogo složenija realizacija sistema.

**Power Shut-Off** (PSO) ili **Power Gating** tehnika gde se isključuju delovi sistema koji trenutno ne rade.

**Adijabatske tehnike** - deo energije se vraća u izvor za napajanje umesto da se disipira.  Veoma efikasno na nižim učestanostima, ali se ne može koristiti za širok opseg učestanosti.

Potrošnja uređaja sa istim hardverom veoma  zavisi od toga kako je napisan aplikativni softver.

## Verifikacija i testiranje

**Verifikacija** pripada fazi projektovanja IK i odnosi se na pronalaženje grešaka u dizajnu.

**Testiranje** se izvodi tokom proizvodnje IK i kasnije tokom rada uređaja. 

Kada se greške u dizajnu uoče verifikacijom, dosta lako i jeftino se mogu ispraviti. Najskuplje je kada loše projektovan uređaj dođe do kupca i tada se otkrije greška.

Simulacije se ubrzavaju tako što se modul koji je najzahtevniji za proveru sintetiše u **hardverskom akceleratoru** (obično FPGA based).

**Emulacija** - Dizajn se mapira na ploču za emulaciju koja obično sadrži više FPGA ili specijalizovanih procesora. Ploča emulira i pinove, tj. dobija se realan hardver za proveru.

**Formalna verifikacija**:
- Provera svojstava ili ekvivalencije (zlatni model)
- Zasniva se na matematičkim modelima sistema i specifikacija

**Semi-formal verifikacija**:
- Kombinacija simulacija i formalne verifikacije

**SoC verifikacija** (High-Level Verification):
- Provere na nivou sistema

### Funkcionalna verifikacija

Bazira se na simulacijama sa automatski generisanim slučajnim vektorima, proverava se odziv i prikupljaju rezultati.

Tok funkcionalne IP verifikacije:

- Analiza specifikacija sistema
- Kreiranje test plana
- Razvoj verifikacionog okruženja
- Testiranje – pronalaženje bagova u dizajnu ili njegovom okruženju
- Analiza pokrivenosti grešaka

Okruženje može biti:
- Determinističko
- Bazirano na random signalima
- Formalno
- Test case generator

Bez obzira na vrstu okruženja, kreira se referentni model u kome se na osnovu zadatih testova određuje očekivani odziv sistema. Referentni model se poredi sa odzivom DUT-a dobijenim tokom verifikacije.

**Direktno zadavanje testova** - definišu se stanja DUT-a koja treba proveriti na osnovu specifikacija i graničnih slučajeva i pišu se direktni testovi.

**Constrained Random Coverage Driven Verification** (CRCDV) - definišu stanja DUT-a koja treba proveriti na osnovu specifikacija i graničnih slučajeva, a stimuli vektori se automatski generišu, uz ograničenja koja postavlja inženjer.

**e jezik**:
- Prvi jezik namenjen isključivo za verifikaciju
- Dobija se kod prilagođen za ponovno korišćenje
- Randomizovano generisanje signala uz poštovanje zadatih ograničenja
- Aspektno orijentisan programski jezik

**eRM metodologija**:
- Prva reuse metodologija koja je imala široku primenu 
- Ključ je organizovanje e koda u eVC – konfigurabilnu verifikacionu komponentu
- Arhitektura eVC-a: Agent, Bus monitor, Signal mapa, Config

**Universal Verification Methodology (UVM)** - Slični koncepti kao kod eRM
- reuse metodologija i slučajno zadavanje testova
- Tipična arhitektura verifikacionog okruženja

Osnovu verifikacionog okruženja čine UVM agenti koji imaju:
- Sekvencer-napredni generator stimulusa koji ima kontrolu nad transakcijama
- Drajver-aktivna komponenta koja uzima transakcije od svog sekvencera i kontroliše signale na interfejsu DUT-a
- Monitor-pasivna komponenta, koja posmatra signale na interfejsu DUT-a  i sakuplja pokrivenost

### Razvoj

- Accellera-asocijacija osnovana 2000. god sa ciljem da se ustanove standardi i nove metodologije za verifikaciju
- Verisity, izraelska firma, razvila e-jezik i e Reuse Methodology (eRM)
- Synopsys razvija novi jezik VERA i Reference Verification Methodology (RVM) 
- Accellera kreira novi jezik SystemVerilog, koji proglašava za standard
- Synopsys i ARM kreiraju Verification Methodology Manual(VMM) za SystemVerilog
