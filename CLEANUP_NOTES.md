# Code Hygiene Backlog

Temporäre Sammel-/Diskussionsdatei. Einträge werden während der Review-Session
gesammelt und erst nach grünem Licht abgearbeitet.

Legende:
- **[S]** simpel / mechanisch (kann der Reviewer direkt machen)
- **[M]** mittel (kleiner Refactor, lokal)
- **[L]** groß (Architektur / crate-übergreifend — vorher abstimmen)
- **[BUG]** tatsächlicher Bug (nicht nur Hygiene)
- **[?]** zu diskutieren, Richtung offen

Status-Spalte: `open` / `wip` / `done` / `skipped`.

---

## 1. Build-blocker / unmittelbar

| # | Status | Größe | Thema | Notiz |
|---|--------|-------|-------|-------|
| 1.1 | open | [S] | `cargo clippy --workspace --all-targets` bricht ab | `reticulum-core/src/resource/msgpack.rs:652` + `:670` — Test-Floats `3.14159` / `3.14` triggern `clippy::approx_constant` (deny-by-default). Fix: andere Dummy-Werte oder `#[allow]` mit Begründung. |

## 2. Clippy-Warnings (aus `cargo clippy --workspace --all-targets`)

Aktueller Stand vor Cleanup — Zahlen werden verifiziert, sobald die 2 Build-Errors
oben weg sind und `clippy` bis zum Ende durchläuft.

| # | Status | Größe | Thema | Notiz |
|---|--------|-------|-------|-------|
| 2.1 | open | [S] | `needless_borrow` (~6x) | Diverse Tests in `reticulum-std/tests/rnsd_interop/*` — `&link_id_a` wo `link_id_a` reicht. Mechanisch per `cargo clippy --fix`. |
| 2.2 | open | [S] | `manual_range_contains` (3x) | Auf `Range::contains` umstellen. |
| 2.3 | open | [S] | `needless_borrows_for_generic_args` (2x) | z.B. `hex::encode(&request_id)`. |
| 2.4 | open | [S] | `assert_eq!(x, true)` | Durch `assert!(x)` ersetzen. |
| 2.5 | open | [S] | unused variables `responder`, `remote_dest_hash` | Mit `_` prefixen oder weg. |
| 2.6 | open | [S] | unused import `alloc::vec` | Entfernen. |
| 2.7 | open | [S] | `map(identity)` / no-op operation / `u8 as u8` Cast | Jeweils entfernen. |
| 2.8 | open | [S] | `field resource_hash is never read` | Prüfen ob Feld wirklich tot oder nur ungelesen gehalten (Serde etc.). |
| 2.9 | open | [M] | `very complex type` | Type-Alias extrahieren. |

## 3. Struktur / Dateigröße

| # | Status | Größe | Thema | Notiz |
|---|--------|-------|-------|-------|
| 3.1 | open | [L/?] | `reticulum-core/src/transport.rs` hat **15906 Zeilen** | Untersuchen, ob natürliche Split-Achsen existieren (Announce-Handling, Path-Discovery, Link-Routing, Tests). Vorsicht: großer Eingriff, eigene Runde. |
| 3.2 | open | [M/?] | `reticulum-core/src/node/mod.rs` (6756), `link/mod.rs` (3847), `destination.rs` (2009), `rnode.rs` (1886) | Kandidaten für Untermodul-Split — pro Datei einzeln bewerten. |
| 3.3 | open | [M] | `reticulum-integ/src/executor.rs` (3955) | Test-/Harness-Code — nach Funktion gruppieren? |

## 4. TODO / FIXME / HACK Audit

| # | Status | Größe | Thema | Notiz |
|---|--------|-------|-------|-------|
| 4.1 | open | [S] | 9 Vorkommen von `TODO`/`FIXME`/`XXX`/`HACK` in 5 Dateien | Durchgehen: jedes entweder fixen, in Issue/Backlog überführen, oder mit konkreter Begründung stehen lassen. Dateien: `reticulum-cli/src/lncp.rs`, `lns.rs`, `reticulum-std/src/interfaces/rnode.rs`, `reticulum-nrf/src/usb.rs`, `reticulum-ffi/src/lib.rs`. |

## 5. Tote Code-Pfade / Dead Code

| # | Status | Größe | Thema | Notiz |
|---|--------|-------|-------|-------|
| 5.1 | open | [S/M] | `cargo machete` Erstlauf erledigt (2026-04-15). Verdächtige unbenutzte Deps: `reticulum-core`: `curve25519-dalek`, `zeroize`. `reticulum-std`: `bytes`, `md-5`. `reticulum-ffi`: `libc`, `reticulum-std`. `reticulum-nrf`: `cortex-m-rt`, `nrf-mpsl`. **Achtung:** machete liefert False Positives bei macro-only-Deps (z.B. `cortex-m-rt` via `#[entry]`) und re-exports. Pro Treffer entscheiden: echte Entfernung oder `[package.metadata.cargo-machete] ignored = […]` mit knappem Grund. |
| 5.2 | open | [S] | `#[allow(dead_code)]` Audit — noch zu kartieren. 31 Treffer siehe §11.3. |

## 6. Formatierung / Konsistenz

| # | Status | Größe | Thema | Notiz |
|---|--------|-------|-------|-------|
| 6.1 | open | [S] | `cargo fmt --check` Status prüfen |
| 6.2 | open | [?] | Ein einheitlicher Stil für `use`-Gruppierung? |

## 7. Code-Kommentare (Hauptrunde)

### Zielbild
- Kommentare müssen den **aktuellen** Code beschreiben, nicht die Historie.
- Kurz und knapp, kein Fließtext.
- Kein AI-Stil: keine `—` (em-dash) in Kommentaren, keine Aufzählungen mit `-` in Kommentar-Blöcken, keine Banner-Divider aus Box-Drawing-Zeichen, keine `NOTE:`/`Important:`-Deko.
- Für **flüchtige Leser** verständlich: keine internen Bug-Nummern, keine "Phase 2a (C5)"-Codes, keine Pfade nach `~/.claude/...`, keine Datums-Stempel von Capture-Dateien.
- Nur wenn das *Warum* nicht offensichtlich ist → knapper Kommentar. Sonst weg.

### Inventur

| Muster | Vorkommen | Dateien | Maßnahme |
|--------|-----------|---------|----------|
| `Bug #N` Referenzen | 42 | 13 | Inhalt rausziehen, danach Nummer entfernen. Falls der Kommentar sonst nichts Neues sagt → löschen. |
| `Phase 2a` / `(C5)` / `(D1)` Sub-Codes | 30 | 9 | Komplett streichen oder durch eine knappe Sachaussage ersetzen. |
| Verweise auf `~/.claude/…` Dateien | 3 | 2 | Immer weg — die Dateien sind für Leser nicht erreichbar. Wenn Inhalt relevant ist, kurz inlinen. |
| Datums-Captures (`2026-04-13 T22-31-48 capture` etc.) | mehrere | `runner.rs`, `rnode.rs` | Weg. Hinweise auf nicht committete Logs sind Müll. |
| Em-Dash `—` in Line-Comments | 679 | 85 | Durch `.` / `:` / Satzende ersetzen, wenn unnötig. Bei Bedarf Satz umformulieren. |
| Bullet-Points in Kommentaren (`/// - x`) | 294 | 48 | Einzeln prüfen: meist durch Fließsatz oder einfache Kommaliste ersetzen; bei echten Enumerationen in Rustdoc stehen lassen, aber nur wenn sinnvoll. |
| Box-Drawing-Divider (`───`) | 485 | 50 | Weg. Code braucht keine Banner. |
| `NOTE:`/`Note that`/`Important:` | 46 | 24 | Deko weg, reine Aussage behalten. |

### Arbeitsplan (erst nach Grünes-Licht)

1. **Pass A — "toxische" Referenzen zuerst** (`[S]`, rein mechanisch):
   - Alle `~/.claude/…` Erwähnungen entfernen bzw. Sachinhalt retten.
   - Alle `Bug #…` + `Phase 2a (…)`-Codes entfernen. Vorher pro Treffer entscheiden: bleibt eine Sachaussage übrig? Wenn nein, ganzer Kommentar weg.
   - Datums-Capture-Referenzen entfernen.
2. **Pass B — Stil** (`[S/M]`, Datei für Datei):
   - Box-Drawing-Divider entfernen.
   - Em-Dashes in Kommentaren entfernen / umformulieren.
   - Bullet-Listen zusammenziehen.
   - `NOTE:`/`Important:`-Deko strippen.
3. **Pass C — Outdated** (`[M/?]`, pro Datei, langsam):
   - Kommentar vs. Code querlesen. Wenn Kommentar lügt → korrigieren oder löschen.
   - "Geschwätzkommentare" (paraphrasieren nur die Zeile darunter) → löschen.
4. **Pass D — Crate-/Modul-Doku** (`[?]`):
   - `//!`-Blöcke auf Aktualität prüfen. Crate-Level-Doku (`reticulum-core/src/lib.rs` etc.) kritisch lesen.

### Prinzipien für Entscheidungen am Einzelfall

- Wenn der Kommentar nur erklärt, *was* der nächste Zeile ohnehin sagt → weg.
- Wenn er Historie referenziert ("we used to …", "removed in Bug #X") → weg.
- Wenn er ein nicht-offensichtliches *Warum* festhält (Invariante, Protokoll-Detail, Python-RNS-Kompat, Interop-Zwang) → behalten, aber ohne Bug-Referenz umschreiben.
- Wenn er auf eine Reticulum-Protokoll-Eigenart verweist, Link auf `vendor/Reticulum` ist erlaubt, weil das Repo-intern ist.

**Entscheidung 2026-04-15 (Bug-#-Kommentare):** `Bug #N …`- und `Phase 2a (X)`-Kommentare werden nicht pauschal entfernt. Vorgehen: Inhalt lesen, Sachargument erkennen — wenn der Kommentar echten Mehrwert für den flüchtigen Leser enthält (nicht-offensichtliche Invariante, Protokoll-Detail, Python-RNS-Parität), knapp umformulieren ohne Bug-Referenz. Wenn der Kommentar außer der Bug-Referenz nichts Eigenes sagt, ganz löschen.

### Weitere Muster (ergänzt)

| Muster | Vorkommen | Maßnahme |
|--------|-----------|----------|
| Auskommentierter Code (`// let x = …`, `// fn …`, `// return …`) | grob 52 Treffer (mit Falsch-Positiven, da Regex Prosa triggert) | Datei-für-Datei sichten, echten auskommentierten Code löschen. Grundregel: auskommentierter Code gehört nie ins Repo. Wenn man ihn "nur zur Sicherheit" aufhebt, ist das Git-Historie-Aufgabe. |
| Historien-Prosa (`previously`, `used to`, `was removed/replaced`, `no longer`, `formerly`) | 28 Treffer / 12 Dateien | Löschen. Git-Log ist die Quelle. Wenn nach dem Löschen eine Invariante fehlt, diese knapp aussagen ohne Zeitbezug. |
| `this commit/fix/change/PR`, "recently added" | 9 / 7 | Löschen — referenziert ein Ereignis, das der Leser nicht sehen kann. |
| Versionen / 7–40-stellige Hex-Strings in Prosa (potenzielle Commit-Hashes) | 86 Treffer — überwiegend legitim (Identity-Hashes, Protokoll-Konstanten, Test-Vektor-Keys). | Nur Treffer anfassen, die klar Git-Hashes sind. Manuell sichten. |
| "for now" / "temporary" / "workaround" / "hack" / "cleanup later" | 25 / 17 | Jedes einzeln: echte Datasheet-Workarounds (`sx1262.rs`) bleiben; "for now" ohne Grund → fixen oder Kommentar entfernen. |
| `unwrap() is safe because …` / "cannot fail" / "never fails" / "invariant …" in Kommentaren | ca. 434 Treffer (mit Falsch-Positiven aus Test-Assertions) | Saftey-Kommentare müssen die Invariante benennen, nicht beteuern. Wenn der Grund nicht präzise steht → umschreiben oder auf `expect("konkrete Invariante")` umstellen. |
| `TODO(name)` / `@username` | 1 Treffer insgesamt | Einzeln prüfen. |
| Emojis / Unicode-Symbole (`✓ ✗ → ↑ ⚠`) in Kommentaren/Code | 354 / 52 | Entfernen. Stil-Ballast. |
| Git-Commit-Hashes in Kommentaren | — | Beim Sichten extrahieren, im Zweifel löschen. |
| Leere `///` Doc-Lines als Absatzpuffer | 1198 Treffer | Nur echte Deko-Leerzeilen zusammenziehen. Absatzbrüche in Rustdoc sind okay. Nicht pauschal anfassen. |
| Banner aus `=====`, `-----`, `*****` als Divider | 4 Treffer | Löschen. |

### Tests nach jedem Pass

Gemäß `CLAUDE.md`: `cargo test-core` + `cargo test-interop` müssen grün bleiben. Kommentare dürfen nichts ändern — aber nach Pass C evtl. Docstring-Tests (`cargo test --doc`) prüfen.

## 11. AI-Agent-typische Muster

Die Codebase ist größtenteils von AI-Agents geschrieben. Typische Kategorien, die wir suchen und aufräumen — getrennt von reinen Kommentar-Themen in Sektion 7.

### 11.1 Kontext-Leck in Code und Kommentaren
Agent arbeitet in kurzen Fokus-Fenstern und hinterlässt seinen Arbeits-Kontext im Code.
- **Bug-Nummern, Phasen-Codes** (`Bug #3 Phase 2a (C5)`) — Sektion 7, Pass A.
- **Capture-/Log-Zeitstempel** im Code.
- **Pfade nach `~/.claude/…`** — Sektion 7, Pass A.
- **"Plan-Labels"** wie `(E1)/(E2)/(D1)/(F4)`: das ist Agenten-Merkzettel, kein Code-Leser-Wissen.

### 11.2 Patchwork statt Root-Cause
Agent fixt Symptome lokal, weil er das Gesamtbild nicht halten kann.
- Mehrere ähnliche-aber-leicht-unterschiedliche Helper-Funktionen für dasselbe Problem.
- Scattered Constants: ein Magic-Value (Timeout, Buffersize) taucht an mehreren Call-Sites auf, statt einmal zentral.
- **Audit:** dubletten-Grep auf `tokio::time::sleep`, `Duration::from_`, `const …`-Werte. (Noch durchzuführen.)
- **Audit:** ähnliche Helper in `transport.rs` / `node/mod.rs` identifizieren.

### 11.3 Angst vor dem Löschen
Agent lässt lieber Code stehen, statt ihn zu entfernen.
- Auskommentierter Code — Sektion 7 "Weitere Muster".
- **`#[allow(...)]` ist grundsätzlich ein Code Smell.** Details in §15 (Allow-Policy).
- **`#[ignore]`-Policy (User-Entscheidung 2026-04-15):** `#[ignore]` ist ausschließlich für Tests zulässig, die Funk-Hardware (RNodes / LNodes, LoRa-Modems) voraussetzen. Jeder andere Grund ist eine Policy-Verletzung — solche Tests werden gefixt oder gelöscht.
- Realer Stand (nach Prüfung 2026-04-15):
  - `reticulum-integ/src/executor.rs`: 71× `#[ignore]`, alle mit "Requires RNode hardware"-Kommentar → legitim.
  - `reticulum-std/src/interfaces/rnode.rs`: 2× "Requires RNode hardware at /dev/ttyACM0" → legitim.
  - `reticulum-std/tests/rnsd_interop/auto_interop_tests.rs:906`: 1× `#[ignore = "same-machine Python↔Rust data port conflict: Python socketserver lacks SO_REUSEPORT"]` → **Policy-Verletzung.** Fixen (z.B. Tests auf verschiedene Maschinen / Ports trennen, oder SO_REUSEPORT-Workaround server-seitig) oder löschen.
  - `reticulum-ffi/tests/ffi_c_tests.rs:30`: 1× `#[ignore = "FFI crate is outdated — will be redesigned after core stabilizes"]` → Out-of-scope, siehe §9.2. Das Crate als Ganzes ist Stub; der Test bleibt ignoriert und begründet.
- Frühere "77 in 6 Dateien"-Zahl war falsch — kam von Grep-Treffern in Doc-Kommentaren.
- Verwaiste Trait-Methoden / Impls ohne Aufrufer.

### 11.4 Verteidigungs-Overhead
Agent versichert lieber zu oft als zu wenig.
- Belt-and-suspenders: dieselbe Validierung entlang des Call-Pfads mehrfach.
- `if let Some(x) = …` für Werte, die per Typ-System bereits `Some` sein müssen.
- Error-Behandlung für Fehler, die nicht auftreten können (z.B. Fehler bei `Vec::push`).
- Redundante Sicherheits-Kommentare an `unwrap()` ohne konkrete Invariante (siehe 7 "Weitere Muster").
- **Audit:** `.clone()` auf `Copy`-Typen oder auf Dingen, wo ein Borrow reichen würde — 301 `.clone()` in 58 Dateien, stichprobenartig sichten.
- **Audit:** `Arc<Mutex<…>>` / `Arc<RwLock<…>>` 35 Treffer / 11 Dateien — fast alles im Treiber-Layer (`driver/mod.rs` 9×, `rpc/mod.rs` 6×). Prüfen ob wirklich geteilter State nötig ist oder nur "async sicher gefühlt".

### 11.5 Print-Debugging bleibt stehen
Agent löscht seine Diagnose-Prints nicht.
- `eprintln!` / `println!` / `dbg!` an Zeilenanfang: **1067 Treffer / 49 Dateien.** Legitim in `reticulum-cli/*` und `examples/`. Problematisch in `reticulum-std/tests/rnsd_interop/*` (Summen im 20–90er-Bereich pro Test-Datei) — auf `tracing`/`log` umstellen oder löschen. Im Bibliothekscode (`reticulum-core`, `reticulum-std/src`) sollte gar keines stehen. Separat auditieren.
- **Entscheidung 2026-04-15:** Out-of-scope für diese Cleanup-Runde. Bleibt erstmal überall drin.

### 11.6 Gigantische Dateien
Agent hängt oben an, statt umzustrukturieren.
- `reticulum-core/src/transport.rs` ~16k Zeilen (Sektion 3).
- `reticulum-core/src/node/mod.rs` ~6.7k.
- **Audit:** Ist jeweils ein sinnvolles Submodul-Split-Muster erkennbar? Separat planen (groß, [L]).

### 11.7 Over-Engineering ohne Konsument
Agent entwirft gerne Trait-Hierarchien, die nur einen Impl haben.
- **Audit:** Traits mit nur einer `impl`-Stelle — Kandidaten: sind sie echt austauschbar (Test-Stub zählt) oder nur Deko?
- Generics ohne zweite Monomorphisierung.

### 11.8 Test-Drift
Tests werden angehäuft statt kuratiert.
- Nahezu-identische Test-Dateien (`link_tests.rs`, `link_manager_tests.rs`, `link_keepalive_close_tests.rs`) — Überschneidungsanalyse offen.
- Harness-Duplikation (`harness.rs` 2063 Zeilen vs. `common.rs`).
- Tests, die Implementierung statt Verhalten testen → anfällig gegen Refactoring. Qualitativ, kein Grep.
- Debug-Prints in Tests (siehe 11.5).

### 11.9 Inkonsistente Konventionen
Agent hat die Hausregeln pro Aufruf neu erfunden.
- Benennungs-Varianten für denselben Begriff (Beispiel: `announce` vs. `Announcement` vs. `ann_packet`).
- Uneinheitliche Error-Typen (`Result<_, &'static str>` neben `thiserror`-Enums).
- `use`-Gruppierung (siehe Sektion 6).

### 11.10 "Nützliche" Hilfsfunktionen ohne Aufrufer
Agent baut vorsorglich Utility, die niemand nutzt.
- **Audit:** `cargo +nightly udeps` für unbenutzte Deps. `cargo machete` als Alternative.
- Clippy-`dead_code`-Warnings ernst nehmen statt `#[allow]`.

### 11.11 Doc-Kommentar ≠ Signatur-Echo
Agent paraphrasiert die Funktion-Signatur in der Doc.
- `/// Returns the foo for the given bar.` über `fn foo(bar: Bar) -> Foo` — weg.
- Nur behalten, wenn die Doc **Invariante, Pre-/Postcondition oder Semantik** nennt, die aus der Signatur nicht hervorgeht.

### 11.12 Sicherheitsnetze um Sicherheitsnetze
- Doppelte Validierung auf beiden Seiten einer Grenze.
- `.max(0).min(MAX).clamp(…)`-Ketten.

---

## 12. Magic Numbers

### Ausgangslage (gut)
- `reticulum-core/src/constants.rs` existiert, **125 benannte Konstanten**, nach Themen gruppiert (Protocol / Keys / Ratchet / Transport / Link / Channel / Proof / Resource / Stream / IFAC / CRC / Token / Signaling / BLE). Das ist die Zielrichtung, nicht das Problem.
- Crate-weit **502 `const …:` Definitionen in 67 Dateien** — viele davon sind legitim file-lokal.
- Stichprobe `reticulum-core/src/*` mit `Duration::from_secs(magic)`: **keine Treffer** — Core holt Durations aus Konstanten. Gut.

### Problem-Zonen

| Zone | Symptom | Dateien/Beispiele |
|------|---------|-------------------|
| 12.A | Raw-Zahlen in Library-Code außerhalb von core | `reticulum-std/src/interfaces/tcp.rs:470` `Duration::from_millis(500)`, `rnode.rs:952` dito, `rnode.rs:31` `FINAL_SETTLE = 300ms` (File-local, aber ohne Begründung), `rnode.rs:477` `HEARTBEAT_INTERVAL = 300s`. Prüfen: gehört in `constants.rs` (protokollrelevant) oder File-Konstante (implementierungsrelevant)? |
| 12.B | `tokio::time::sleep/timeout(Duration::from_...)` mit Magic-Zahlen | **441 Treffer / 49 Dateien**, überwiegend Tests, aber auch Produktivcode. Bulk: `transport_interop_tests.rs` 18×, `link_manager_tests.rs` 32×, `link_tests.rs` 11×, `encryption_tests.rs` 22×, `comprehensive_network_test.rs` 9×, `mtu_tests.rs` 30×. |
| 12.C | Testdateien mit `Duration::from_secs(…)` voll verstreut | **832 Treffer / 60 Dateien.** Keine einheitliche Test-Timeout-Quelle. Vorschlag: `reticulum-std/tests/rnsd_interop/common.rs` bündelt die Standard-Timeouts (`PROPAGATE_TIMEOUT`, `LINK_ESTABLISH_TIMEOUT`, `SHORT`, `LONG`) und alles andere ist Ausnahme mit Kommentar *warum*. |
| 12.D | Große numerische Literale in `transport.rs` | **306 Zeilen mit ≥3-stelligen Zahlen** in einer Datei. Muss gesichtet werden: Bitmasken/Protokoll-Bytes sind okay (auch wenn viele bereits in `constants.rs` stehen — ggf. konsolidieren), echte Magic Numbers rausziehen. |
| 12.E | Embedded-Layer `reticulum-nrf/src/sx1262.rs` | **39 file-lokale `const` + viele Hex-Werte.** Datasheet-Register-Adressen sind legitim, aber Magic-Masken sollten einheitlich benannt sein. |

### Policy (Vorschlag)
1. **Protokoll-/Wire-Format-Zahlen** (Timeouts, die mit Python-RNS übereinstimmen müssen, Paketgrößen, Bit-Flags): gehören in `reticulum-core/src/constants.rs` mit knappem `/// Python Reticulum …`-Hinweis. Das ist der Ort, an dem der Leser suchen soll.
2. **Implementierungs-spezifische Zahlen** (Buffer-Kapazitäten, Retries, file-lokale Tuning-Parameter): File-lokale `const UPPER_SNAKE`, direkt über der ersten Verwendung, mit Einzeiler *warum dieser Wert*.
3. **Tests**: Standard-Timeouts in `tests/rnsd_interop/common.rs`. Per-Test-Overrides nur mit Begründungs-Kommentar.
4. **Datasheet-Register / Protocol-Konstanten in Embedded-Code**: eigenes `constants.rs` / `regs.rs`-Modul pro Chip, mit Datasheet-Seitenangabe.
5. **Nicht zentralisieren**: triviale Werte (`0`, `1`, `2`, `-1`, `100%`, Array-Indizes), Testdaten-Seeds.

### Arbeitsplan
1. **Pass A — Tests konsolidieren** (`[S/M]`): einmalig `tests/rnsd_interop/common.rs` um Standard-Timeout-Konstanten erweitern, Test-Dateien umstellen. Risikoarm: Verhalten bleibt, nur Bezeichner ändern sich. Verifikation: `cargo test-interop`.
2. **Pass B — Library-Layer** (`[M]`): `reticulum-std/src/interfaces/*` sichten, raw Durations → File-Konstante oder `constants.rs` (wenn Python-RNS-parity).
3. **Pass C — Transport-Magic-Numbers** (`[M/L]`): `transport.rs` sampeln, offensichtliche Magic Numbers extrahieren. Vorsichtig, weil große Datei.
4. **Pass D — Embedded** (`[M]`): `reticulum-nrf/src/sx1262.rs` Register-Konstanten vereinheitlichen. Nur wenn gewünscht (Embedded-Änderungen haben eigenes Risikoprofil — Hardware-Tests laufen nachts).

### Heuristik beim Entscheiden
- Kommt dieselbe Zahl ≥2× vor? → Konstante.
- Steht die Zahl im Python-RNS-Source? → `constants.rs`, Python-Verweis im Doc-Kommentar.
- Ist der Wert empirisch gewählt ("probiert bis es ging")? → File-Konstante + Kommentar warum genau dieser Wert (Mess-Ergebnis, Hardware-Grenze, …).

## 13. Duplizierter Code

AI-Agents kopieren bevorzugt, statt Factorisierung zu suchen. Erste Befunde:

### 13.1 Test-Helper-Duplikation (höchste Priorität, risikoarm)

| Helper | Vorkommen | Sollort |
|--------|-----------|---------|
| `create_link_raw` | 3× (`link_tests.rs`, `resource_tests.rs`, `responder_node_tests.rs`) | `tests/rnsd_interop/common.rs` |
| `establish_rust_to_rust_link` | 2× | `common.rs` / `harness.rs` |
| `build_rust_node` | 2× | `common.rs` / `harness.rs` |
| `temp_storage` | 2× | `common.rs` |
| `cleanup_config_dir` | 2× | `common.rs` |
| `wait_for_*` Familie | `common.rs` hat 21 Varianten, Test-Dateien definieren weitere 6+ (`ratchet_tests.rs` 2, `proof_tests.rs` 2, `resource_tests.rs` 1, `harness.rs` 1) | Alles nach `common.rs` mit gemeinsamer Poll-Loop-Abstraktion. |
| `msgpack_encode_bin` / `msgpack_decode_bin` in `resource_tests.rs` | Dupliziert die Public-API aus `reticulum-core/src/resource/msgpack.rs` | Core-Funktionen nutzen. |

**Typischer Template-Code für `wait_for_X`:**
```rust
async fn wait_for_X(events, target, timeout) -> Option<…> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(evt) = events.recv().await { if matches!(evt, …) { return Some(…) } }
    }
    None
}
```
Alle 27+ Varianten unterscheiden sich nur im Matcher und dem Rückgabetyp. → Ein Generic `wait_for(events, timeout, |evt| -> Option<T>)` würde die Schar kollabieren.

### 13.2 Core-Duplikate (mittlere Priorität, vorsichtig)

| Kandidat | Vorkommen | Aktion |
|----------|-----------|--------|
| `dispatch_actions` | 4× über `core`/`std`/`nrf`/tests (`traits.rs`, `node/mod.rs`, `transport.rs`, `driver/mod.rs`, `interfaces/mod.rs`, `t114.rs`, sowie Tests) | Prüfen: gibt es eine kanonische Stelle oder sind das bewusst verschiedene Operationen pro Layer? Vermutlich gibt es *eine* richtige Stelle und der Rest sind Weiterleitungen, die sich wegfallen lassen. |
| msgpack-Encoder (`write_uint`, `write_nil`, `write_fixstr`, `write_fixmap_header`, `write_fixarray_header`, `write_bool`, `write_bin`) | jeweils 1× in `resource/msgpack.rs` | Ok — aber: wird im RPC-Layer (`rpc/pickle.rs`) oder in Tests parallel dazu kleiner msgpack-Handcode gestrickt? Zu prüfen. |
| `constant_time_eq` | 2× | Kanonisieren. Subtile Unterschiede können Sicherheitsproblem sein. |
| `now_ms` | 2× | Einheitlich aus `reticulum-std/src/clock.rs` oder `reticulum-core` ziehen. |

### 13.3 Strukturelle Duplikate (zur Diskussion)

| Verdacht | Prüfung |
|----------|---------|
| Test-Dateien `link_tests.rs`, `link_manager_tests.rs`, `link_keepalive_close_tests.rs` | Überlappungs-Audit: teilen die Tests Setup/Teardown? Mit common.rs-Ausbau wahrscheinlich ~30 % Zeilen einsparbar. |
| `harness.rs` (2063 Zeilen) vs. `common.rs` | Zweck der Trennung klären. Wenn beide Test-Helper hosten: mergen oder scharf abgrenzen (z.B. `common.rs` = schnelle Stubs, `harness.rs` = Python-Reticulum-Orchestrierung). |
| Interface-Definitionen in `reticulum-std/src/interfaces/{tcp,udp,local}.rs` | Vermutlich viele ähnliche `spawn`/`event_loop`/`read_loop`-Muster. Mit einem gemeinsamen `InterfaceBackend`-Trait oder Helper einsparbar — aber: echter [L]-Refactor. |
| Retry-Schleifen (`tokio::time::sleep` + `attempts +=`) | Einheitliche Retry-Abstraktion sinnvoll? Kandidat: kleiner Helper in `reticulum-std`. |

### Arbeitsplan

1. **Pass A — Test-Helper** (`[M]`): 13.1 konsolidieren. Mechanisch: Funktionen nach `common.rs`, `use common::…;` überall. `cargo test-interop` muss grün bleiben. Erwarteter Netto-Effekt: mehrere 100 Zeilen weg.
2. **Pass B — Core-Duplikate sichten** (`[M/?]`): 13.2 einzeln, jeder Treffer ein eigener kleiner Refactor mit `cargo test-core` danach. `constant_time_eq` zuerst (Sicherheit).
3. **Pass C — Struktur** (`[L]`): 13.3 nur nach expliziter Freigabe, Einzelplan.

### Was wir NICHT verdächtig finden sollten

- Boilerplate aus `Serialize`/`Deserialize`-Impls.
- Wiederholte Test-Assertion-Patterns (können bleiben, wenn sie Lesbarkeit erhöhen).
- Kopien, die bewusst divergieren (z.B. `no_std`-Variante vs. `std`-Variante desselben Algorithmus).

---

## 14. Werkzeuge

Stand nach `tokei`: **83 229 Zeilen Rust-Code + 8 208 Zeilen Doc-Kommentare + 15 357 Leerzeilen** in 167 Dateien. Das ist zu groß für handgemachte Greps. Diese Tools sind installiert und gezielt für den Cleanup einzusetzen:

### 14.1 `tokei` — Zeilen-Inventur
- **Wofür:** Schnelle Übersicht pro Crate/Dir, Fortschritts-Messung des Cleanups (Code vs. Kommentar vs. Leer).
- **Wann verwenden:** Vor jedem Pass als Baseline, nach jedem Pass zum Diff.
- **Aufruf:** `tokei reticulum-core reticulum-std --sort code`
- **Output nutzen für:** Sektion 3 (Datei-Splits), Sektion 7 (Kommentar-Abbau — Comments-Ratio sollte fallen, nicht steigen).

### 14.2 `fdfind` — schneller `find`-Ersatz
- **Wofür:** Datei-Patterns ohne shell-Glob-Quoting-Drama.
- **Wann verwenden:** Immer wenn `find` gereicht hätte.
- **Aufruf:** `fdfind -e rs -E target -E vendor 'tests?'` (Test-Dateien listen)
- **Alias:** Auf Debian heißt das Binary `fdfind`, nicht `fd`.

### 14.3 `ast-grep` — strukturelle Suche (ersetzt ~80 % unserer Grep-Akrobatik)
- **Wofür:** Rust-AST-Pattern statt Regex. Findet Dinge, die Grep nicht kann.
- **Wann verwenden für unseren Cleanup:**
  - Sektion 7 / Kommentar-Pass A: alle Doc-Kommentare, die nur die Signatur paraphrasieren (AST-Pattern: `doc_comment` matcht `identifier`-Namen direkt darunter).
  - Sektion 11.4: `Arc<Mutex<$T>>` wo `$T` ein `Copy`-Type ist.
  - Sektion 11.7: Traits mit genau einer `impl`-Stelle.
  - Sektion 13.2: Funktionen mit exakt einem Call-Site (Kandidat für Inlining).
- **Aufruf-Beispiele:**
  ```sh
  ast-grep --lang rust -p '$A.clone()' reticulum-core/src
  ast-grep --lang rust -p 'Arc<Mutex<$T>>' reticulum-std/src
  ast-grep --lang rust -p 'fn $N($$$) { $$$ .unwrap() $$$ }'
  ```
- **Policy:** Jedes neue Muster in §7 / §11 bekommt sein ast-grep-Pattern in einer `sgconfig.yml` am Repo-Root (wird bei Pass A angelegt). So sind die Muster reproduzierbar.

### 14.4 `similarity-rs` — semantische Duplikat-Erkennung (Kern-Tool für §13)
- **Wofür:** Findet strukturell ähnliche Rust-Funktionen, auch bei umbenannten Variablen. Genau unser §13-Problem.
- **Wann verwenden:**
  - Vor §13 Pass A: gesamter Test-Tree scannen.
  - Vor §13 Pass B: `reticulum-core/src` + `reticulum-std/src` scannen.
  - Vor §11.6 (Datei-Splits): auf `transport.rs` allein laufen lassen — offenbart oft, dass "riesige Datei" = 3× derselbe Code.
- **Aufruf:** `similarity-rs --threshold 0.85 reticulum-std/tests/rnsd_interop/`
- **Output nutzen:** Findings ergänzen §13 direkt (neue Zeilen anhängen).
- **Achtung:** Threshold-Tuning nötig. <0.8 produziert Rauschen, >0.9 verpasst echte Duplikate mit Unterschied.

### 14.5 `cargo-machete` — tote Workspace-Deps
- **Wofür:** Findet in `Cargo.toml` gelistete Deps, die nicht benutzt werden. Direkter Treffer für §11.10.
- **Wann verwenden:** Einmalig vor Pass A. Bei jeder Änderung an `Cargo.toml` erneut.
- **Aufruf:** `cargo machete` (auf Workspace-Root)
- **Policy:** Findings werden zu §5 hinzugefügt.

### 14.6 `cargo-modules` — Modulgraph
- **Wofür:** Visualisiert, welche Module voneinander abhängen. Unverzichtbar, bevor `transport.rs` oder `node/mod.rs` gesplittet werden (§3, §11.6).
- **Wann verwenden:** Vor jedem [L]-Refactor, der Dateigrenzen verschiebt.
- **Aufruf:** `cargo modules structure -p reticulum-core` oder `cargo modules dependencies -p reticulum-core --layout fdp`

### 14.7 `typos` — Tippfehler
- **Wofür:** Findet Tippfehler in Code-Identifikatoren, Kommentaren, Doc.
- **Wann verwenden:** Einmal am Anfang, dann als Teil der CI-Checks.
- **Aufruf:** `typos reticulum-core reticulum-std reticulum-cli`
- **Policy:** Findings sammeln, echte Fixes sofort, False Positives in `.typos.toml` whitelisten.

### 14.8 `cargo-audit` — Security-Advisories
- **Wofür:** Bekannte CVEs in Deps.
- **Wann verwenden:** Einmalig am Anfang, dann periodisch.
- **Aufruf:** `cargo audit`
- **Policy:** Hygiene-Task bleibt Hygiene; echte CVEs werden als separater Bug behandelt.

### 14.9 `cargo-nextest` — schnelleres Test-Laufen
- **Wofür:** `CLAUDE.md` verlangt Tests nach jedem Pass. nextest läuft parallel und gibt klarere Ausgabe.
- **Wann verwenden:** Als Drop-in für `cargo test` während der Cleanup-Iterationen. Interop-Harness prüfen — manche Integrationstests können seriellen Lauf erfordern.
- **Aufruf:** `cargo nextest run -p reticulum-core`
- **Achtung:** Wenn bestehende `cargo test-core`/`cargo test-interop`-Aliasse spezielle Flags setzen (siehe `Justfile`/`.cargo/config.toml`), nicht blind ersetzen — die Aliasse bleiben kanonisch für die CI.

### 14.10 `cargo clippy` (schon vorhanden)
- **Wofür:** Rust-Linter. Für unseren Cleanup mit `-D warnings` laufen lassen, damit die Zero-Warning-Regel erzwungen ist.
- **Aufruf:** `cargo clippy --workspace --no-deps --all-targets -- -D warnings`
- **Aktueller Status:** bricht mit 2 Errors in `reticulum-core/src/resource/msgpack.rs` (siehe §1.1). Erster Fix-Kandidat.

### 14.11 Bereits verfügbar (aus Host / Claude-Code)
- `ripgrep` via das `Grep`-Tool — für schnelle Inhaltssuche. Weiterhin nützlich, wenn AST nicht hilft (z.B. Kommentar-Scans).

### 14.12 Installation / PATH
- apt-Tools (`tokei`, `fdfind`) liegen unter `/usr/bin`.
- Cargo-Tools liegen unter `~/.cargo/bin`. Dieser Pfad ist in der interaktiven Fish-Shell da, aber **nicht automatisch in non-interactive Bash-Shells**. Vor Skripten: `export PATH="$HOME/.cargo/bin:$PATH"` oder die Tools absolut aufrufen.
- `fd` heißt auf Debian `fdfind` (nicht `fd`).

### Tool-Policy in Kurzform

| Aufgabe | Tool |
|---------|------|
| "Wo steht welche Zeile?" | `ripgrep` (Grep-Tool) |
| "Welcher Code-Pattern tritt auf?" | `ast-grep` |
| "Welche Funktionen sind Quasi-Duplikate?" | `similarity-rs` |
| "Welche Deps sind tot?" | `cargo machete` |
| "Wo hängt was ab?" | `cargo modules` |
| "Schreibt/spricht unser Code korrekt?" | `typos` + `cargo clippy` |
| "Geht unser Dependency-Stack noch?" | `cargo audit` |
| "Wie groß ist das Ding eigentlich?" | `tokei` |
| "Tests nach Pass" | `cargo nextest run` (parallel zu den Projekt-Aliassen) |

---

## 15. Allow-Policy

**Grundsatz:** `#[allow(...)]` ist ein Code Smell. Der Compiler/Linter hat einen Grund zu warnen, und jede Abschaltung ist eine ungelöste Design-Frage. Bevor ein `#[allow]` bleibt, wird ernsthaft geprüft, ob der Code selbst das Problem ist.

### Ist-Zustand

| Allow | Vorkommen |
|-------|-----------|
| `dead_code` | 30 |
| `clippy::too_many_arguments` | 14 |
| `clippy::type_complexity` | 1 |
| `clippy::large_enum_variant` | 1 |
| `unused_mut` | 1 |

### Policy pro Lint

- **`dead_code` — immer umstrukturieren.** Wenn Code wirklich nicht aufgerufen wird → löschen. Wenn er nur für Tests da ist:
  - Ist es eine **Test-Helper-Funktion**? → Nach `mod tests` oder `#[cfg(test)]` verschieben, oder in eine `test_utils`-Crate/-Modul, die nur unter `#[cfg(any(test, feature = "test-utils"))]` kompiliert wird. Dann kein Allow nötig.
  - Ist es ein **Feld, das nur in Tests gelesen wird**? → Entweder (a) in den Test-Code verschieben, (b) das Feld aus dem Produktivcode entfernen und im Test über einen Getter/Constructor mocken, (c) ein Getter/Debug-API exposen, die das Feld legitim nutzt.
  - Ist es ein **Feld das nur geschrieben wird (für Logging/Debug)**? → Entweder wird es per `Debug`-/`Display`-Impl auch gelesen, oder es ist wirklich tot → weg.
- **`clippy::too_many_arguments` — fast immer umstrukturieren.** Drei saubere Wege:
  - Struct / Builder für zusammengehörende Parameter (`LinkConfig`, `AnnounceOptions`).
  - Methode auf einem passenden Receiver, statt die 7 Felder als Argumente zu reichen.
  - Zerlegung: vielleicht macht die Funktion in Wahrheit zwei Dinge.
- **`clippy::type_complexity` — Type-Alias einführen.** `pub type FooCallback = Box<dyn Fn(…) + Send + Sync>;`. Löst den Lint und verbessert die API-Lesbarkeit.
- **`clippy::large_enum_variant` — Variante boxen oder Enum splitten.** Der Lint meint's ernst (Stack-Size, Match-Branch-Kosten).
- **`unused_mut` — kein Allow nötig, einfach `mut` entfernen.**

### Ausnahmen, die durchgehen dürfen (mit knappem Begründungs-Kommentar direkt überm Allow)

1. **FFI-Felder**, die nur C-Seite liest (`#[allow(dead_code)] // read from C`). Vorsicht: meist ist `#[repr(C)]` + Konstruktor + `PhantomData`-Alternative besser.
2. **Macros, die generierten Code enthalten**, für den ein Lint fälschlich anschlägt — dann in der Macro-Expansion das Allow, nicht im Aufrufer.
3. **Externe Trait-Implementierungen**, die eine `too_many_arguments`-Signatur vorgeben (Trait nicht von uns).

### Arbeitsplan für Allow-Tilgung

1. **Pass 1 — `dead_code`** (30 Treffer, `[M]`):
   - Für jeden Treffer `ast-grep --lang rust -p 'fn $N($$$)' <datei>` + Aufruf-Suche. Wenn 0 Aufrufer → löschen. Wenn nur Test-Aufrufer → Helper in `#[cfg(test)]`-Modul, Allow raus.
   - `cargo test-core` + `cargo test-interop` nach jedem Datei-Batch.
2. **Pass 2 — `too_many_arguments`** (14 Treffer, `[M]` pro Stelle):
   - Pro Funktion entscheiden: Config-Struct, Builder, oder Dekomposition.
   - Die 14 Treffer zuerst einzeln auflisten (nächster Durchlauf), dann einzeln planen.
3. **Pass 3 — Rest (3 Treffer)**: Type-Alias / Boxen / `mut` raus.

### Ziel

Nach Abschluss: **0 `#[allow(...)]` in Produktiv-Code.** Erlaubt bleiben nur begründete Ausnahmen in der obigen Liste, jede mit Kommentar `// reason: …`.

---

## 16. Weitere Code Smells

Zusätzlich zu den bisher gelisteten Themen — alle sind reale Refactoring-Kandidaten für diese Codebase. Zum Priorisieren, nicht zur Abarbeitung in dieser Session.

### 16.1 Long Parameter List
- Bereits sichtbar über die 14× `clippy::too_many_arguments`-Allows (§15).
- Scan: `ast-grep --lang rust -p 'fn $N($A, $B, $C, $D, $E, $F, $G, $$$)'`
- Fix-Muster: Konfig-Struct, Builder, oder Funktion in mehrere aufteilen.

### 16.2 Primitive Obsession
Hashes/IDs werden als `[u8; 16]`, `Vec<u8>`, `String` durchgereicht, statt als eigenen Typ.
- Risiko: `DestinationHash` und `TruncatedPacketHash` und `IdentityHash` sehen im Quelltext gleich aus — Vertauschen fällt dem Compiler nicht auf.
- Scan: `ast-grep --lang rust -p 'fn $N($$$, $P: [u8; 16], $$$)'`
- Fix: Newtype-Structs (`DestinationHash(pub [u8; 16])`) mit `Copy`, `Eq`, `Hash`.

### 16.3 Boolean Parameters
`fn send(packet: Packet, retry: bool, urgent: bool, broadcast: bool)` — an der Call-Site ist `true, false, true` unlesbar.
- Scan: `ast-grep --lang rust -p 'fn $N($$$, $P: bool, $$$, $Q: bool, $$$)'`
- Fix: `enum RetryMode { Retry, NoRetry }` oder ein Flags-Struct.

### 16.4 Stringly-typed APIs
Parsen von Enum-artigen Werten aus Strings in der Business-Logic.
- Scan: `ast-grep --lang rust -p 'match $S.as_str() { $$$ }'`, `"some_literal" == $s`.
- Fix: `enum` + `FromStr` an der Grenze, intern nur das Enum benutzen.

### 16.5 Inkonsistente Zeit-Typen
Mix aus `u64` ms, `Duration`, `Instant`, Wall-Clock-Sekunden, die als `u64` durch die API wandern.
- Bereits angedeutet in `clock.rs` und `airtime.rs`. Gefahr: Einheiten verschlucken (Sekunden statt Millisekunden).
- Fix: an Crate-Grenzen `Duration` / `Instant`, nur intern bei Persistenz/Wire-Format `u64 ms` + Newtype (`Timestamp`, `DeadlineMs`).

### 16.6 Silent Truncation / Saturating Math
`as u32`, `.saturating_sub()`, `.wrapping_add()` ohne Begründung — versteckt Overflow-Bugs.
- Scan: `ast-grep --lang rust -p '$X as u32'`, `.saturating_sub($$$)`, `.wrapping_*`.
- Fix: echter `try_into` + Error, oder `saturating_*` mit Begründungs-Kommentar.

### 16.7 God Objects
`Transport` (16k Zeilen), `Node` (6.7k) haben wahrscheinlich viel zu viele Zuständigkeiten.
- Bereits in §3 / §11.6. `cargo modules` + `similarity-rs` einsetzen, bevor gesplittet wird.

### 16.8 Feature Envy
Methode auf `A` greift vorwiegend auf Felder von `B` zu — gehört an `B`.
- Schwer zu automatisieren. Qualitativ beim Durchlesen der großen Dateien.

### 16.9 Temporal Coupling
"Du musst `init()` vor `start()` aufrufen, sonst Panik." Nicht vom Typsystem erzwungen.
- Fix: Typestate-Pattern. `NodeBuilder → Node<Uninitialized> → Node<Running>`.
- Hinweis auf bestehenden Builder in `reticulum-core/src/node/builder.rs` — ggf. ausbauen.

### 16.10 Deeply Nested Conditionals
- Scan: `ast-grep --lang rust -p 'if $A { if $B { if $C { $$$ } } }'`
- Fix: Early returns, `?`-Operator, Guard-Clauses.

### 16.11 Mutable Global State
- Scan: `static mut`, `lazy_static!` ohne Immutable-Annahme, `OnceLock` mit Schreib-API.
- Fix: Dependency-Injection oder explizite Handles.

### 16.12 Exzessives `pub`
Module exportieren Interna. Jede externe API-Fläche ist Refactoring-Last.
- Scan: `cargo modules structure -p reticulum-core --types` → zu viele `pub` unter dem Kopf?
- Fix: `pub(crate)` / `pub(super)` / privat.

### 16.13 Error-Typ-Chaos
Mix aus `Result<_, Box<dyn Error>>`, `&'static str`, `anyhow::Error`, eigene Enums.
- Fix: Pro Crate ein `Error`-Enum (`thiserror`), `anyhow` nur in Binaries (CLI) an der Spitze.

### 16.14 Unsafe-Blöcke
- Scan: `ast-grep --lang rust -p 'unsafe { $$$ }'` in `reticulum-core/src`, `reticulum-std/src` — sollte dort gar nicht vorkommen, außer in klar markierten FFI-Grenzen.
- `reticulum-nrf` (HAL-Zugriff) und `reticulum-ffi` dürfen `unsafe`, müssen aber `// SAFETY:`-Kommentare mit Invariante tragen.

### 16.15 Shotgun Surgery
Signal: eine semantische Änderung (z.B. ein neues Protokoll-Flag) erfordert Edits in 20 Dateien.
- Detektion qualitativ beim Durchsehen einzelner Concepts (z.B. wie viele Dateien kennen `hops: u8`?).
- Fix: Konzept in Typ kapseln (z.B. `HopCount(u8)` mit Inkrement-Semantik).

### 16.16 Race-prone Test Synchronisation
`tokio::time::sleep(Duration::from_millis(50))` als "hoffentlich genug Zeit" — flaky.
- `CLAUDE.md` verbietet flaky explizit. Alle Test-Sleeps sind Verdachtskandidaten.
- Fix: auf Event/Channel warten statt Wall-Clock, oder deterministische Mock-Clock (siehe `reticulum-std/src/clock.rs`).

### 16.17 Catch-all Utility-Module
`utils.rs` / `helpers.rs` / `misc.rs` — sammelt alles, was nirgendwo passt. Symptom fehlender Abstraktionen.
- Scan: `fdfind -e rs 'util|helper|misc'`
- Fix: Inhalt nach thematisch passenden Modulen verteilen.

### 16.18 Redundante Re-Exports
Crate-Wurzel re-exportiert 30 Typen, von denen 5 genutzt werden.
- Scan: `cargo modules structure -p <crate>`.
- Fix: Nur re-exportieren, was wirklich Public-API ist.

### 16.19 Builder ohne Build-Time-Garantien
Builder, dessen `build()` zur Laufzeit scheitert, obwohl man es typstatisch absichern könnte.
- Siehe 16.9 (Typestate).

### 16.20 `format!`-Overhead in Hot-Paths
`tracing::debug!("{}", format!(...))` — das `format!` läuft immer, auch wenn das Log-Level aus ist.
- Fix: `tracing::debug!("{}", value)` mit dem Arg direkt.
- Scan: `ast-grep --lang rust -p 'tracing::$L!("$$", format!($$$))'`.

### 16.21 Inkonsistente Logging-Konventionen
- Mix aus `tracing` / `log` / `eprintln!`?
- Log-Level-Auswahl unbegründet (alles `info!` oder alles `debug!`)?
- Scan: `ast-grep --lang rust -p 'log::$L!($$$)'` vs. `tracing::$L!($$$)`.

### 16.22 Copy-Paste über Feature-Flag-Gates
`#[cfg(feature = "std")] fn foo() { ... }` und `#[cfg(not(feature = "std"))] fn foo() { ... }` mit 90 % gleichem Code.
- Fix: gemeinsame Basis extrahieren, nur echten `cfg`-Teil separat.

### 16.23 Public Types mit Öffentlichen Feldern
`pub struct Foo { pub a: u32, pub b: Vec<u8> }` — jede Field-Änderung ist Breaking Change.
- Fix: Felder `pub(crate)` / privat, Getter/Setter wenn Semantik es erfordert, `non_exhaustive`-Struct-Enums nutzen.

### 16.24 `clone()` als Compiler-Beruhigung
Wenn `.clone()` das Problem "löst", ohne dass der Wert tatsächlich zweimal gebraucht wird, ist es Borrow-Checker-Flucht.
- 301 `.clone()` in 58 Dateien — stichprobenartig sichten (`ast-grep --lang rust -p '$X.clone()'`).

### 16.25 Inkonsistentes `async`-Design
Mix aus `async fn`, `fn(...) -> impl Future<...>`, `Pin<Box<dyn Future>>`.
- Jede Variante hat ihre Rolle, aber innerhalb eines Crates sollte eine Wahl dominieren.

### 16.26 Ratelimit-/Backoff-Duplikate
Vermutlich mehrere lokale Reimplementierungen von Retry-mit-Backoff (Transport, Link, Resource). Siehe §13.3.

### 16.27 Nicht-exhaustive Matches mit `_`
Match-Arm `_ => {}` in Enum-Match: jede neue Variante wird stillschweigend ignoriert.
- Scan: `ast-grep --lang rust -p 'match $E { $$$ _ => {} $$$ }'`.
- Fix: jede Variante explizit matchen oder `#[non_exhaustive]`-Doku für bewusst offene Enums.

### 16.28 Tests in `mod tests` vs. `tests/` inkonsistent verteilt
Manche Unit-Tests sitzen in `src/**/mod.rs` unter `#[cfg(test)]`, andere in `tests/` — ohne klaren Grund.
- Policy festlegen: Unit-Tests im Source-Modul, Integrations-Tests in `tests/`. Audit durchführen.

### 16.29 `panic!` in Library-Code
- Scan: `ast-grep --lang rust -p 'panic!($$$)'` in `reticulum-core/src` und `reticulum-std/src`.
- Fix: `Result` zurückgeben. `panic!` gehört allenfalls hinter `const`-Assertions oder in Tests.

### 16.30 Inline-Konstanten-Duplikate
`const X: u64 = 1000;` in drei Modulen mit gleichem Wert aber unterschiedlichem Namen.
- Zusammenfassen, siehe §12.

---

## 17. Autonomer Ausführungsplan

Ergebnis der Planungs-Session mit dem User am 2026-04-15. Wird von einem späteren Claude-Lauf ohne User-Interaktion durchgearbeitet.

### 17.1 Scope-Einteilung

**Teil A — autonom ausführen (in dieser Reihenfolge):**

1. §1 Build-Blocker beheben (Clippy-Errors in `reticulum-core/src/resource/msgpack.rs`).
2. §2 Clippy-Warnings abarbeiten.
3. §7 Pass A — toxische Kommentar-Referenzen (`Bug #N`, `Phase 2a (X)`, `~/.claude/…`, Capture-Zeitstempel). Regel: Sachinhalt knapp umformulieren wenn Mehrwert; sonst löschen.
4. §7 Pass B — Kommentar-Stil (Box-Drawing-Divider, Em-Dashes in Line-Comments, Bullet-Listen in Kommentaren, `NOTE:`/`Important:`-Deko, Emojis).
5. §12 Pass A — Test-Timeout-Konstanten zentralisieren (`reticulum-std/tests/rnsd_interop/common.rs`).
6. §13.1 — Test-Helper-Konsolidierung nach `common.rs` (`create_link_raw`, `build_rust_node`, `temp_storage`, `cleanup_config_dir`, `wait_for_*`-Familie generisch).
7. §5.1 — `cargo-machete`-Funde einzeln verifizieren; für `reticulum-ffi` als `ignored` eintragen (Stub, §9.2); bei anderen Crates: echte Entfernung nur mit `cargo check --all-features --all-targets`-Durchgang.
8. §11.3 — die eine echte `#[ignore]`-Policy-Verletzung (`auto_interop_tests.rs:906` Port-Conflict) fixen oder löschen. Abbruchregel: wenn Root-Cause nicht in 30 Min gefunden, Befund in Abschlussbericht statt Löschung.

**Teil B — Plan-only, wartet auf separate Freigabe:**
- §3 / §11.6 Datei-Splits (`transport.rs`, `node/mod.rs`).
- §7 Pass C (Outdated-Audit).
- §12 Pass B (`reticulum-std` Library-Layer) + §12 Pass C (`transport.rs` Magic Numbers).
- §15 `#[allow(...)]`-Tilgung.
- §16.x Architektur-Smells (Primitive Obsession, Typestate, Error-Typ-Konsolidierung, Feature-Envy, Shotgun Surgery etc.).

**Out-of-scope:**
- `vendor/Reticulum` (§9.1).
- `reticulum-ffi/` (§9.2 — Stub).
- §11.5 Debug-Prints (User-Entscheidung 2026-04-15, bleiben drin).

### 17.2 Crate-Scope

Teil A wird auf diese Crates angewendet:
`reticulum-core`, `reticulum-std`, `reticulum-cli`, `reticulum-integ`, `reticulum-proxy`, **`reticulum-nrf`** (User-Entscheidung 2026-04-15).

Ausgenommen bleibt `reticulum-ffi`.

Bei `reticulum-nrf` besondere Vorsicht: Hardware-Tests laufen nur nachts, Timing-sensibler Embedded-Code. Datasheet-Verweise in Kommentaren (z.B. `sx1262.rs` "Workaround 15.3 for timed RX") sind **Sachinhalt** und bleiben erhalten — nicht als "Bug #"-artiger Kontext behandeln.

### 17.3 Commit-Politik (User-Entscheidung 2026-04-15)

- **Ein Commit pro Pass.** Jeder Pass aus §17.1 bekommt einen eigenen Commit mit klarer Nachricht.
- **Direkt auf `master`** — kein separater Cleanup-Branch.
- **Vor jedem Commit verpflichtend:** `cargo fmt`, `cargo clippy --workspace --no-deps --all-targets -- -D warnings`, `cargo test-core`, `cargo test-interop`. Rot = nicht committen.
- **Kein Push.** Nach dem Lauf liegt alles lokal; der User reviewt und pusht selbst.
- **Abbruchverhalten:** Wenn ein Pass in sich fehlschlägt und Root-Cause nicht in ≤30 Min findbar ist, Working-Tree auf den letzten grünen Commit hart zurücksetzen (`git reset --hard HEAD`) und im Abschlussbericht notieren, was abgebrochen wurde und warum. Keine halbfertigen Passes auf Platte liegen lassen.
- **Commit-Signatur** gemäß globaler Instruktion: Co-Authored-By-Footer für Claude bleibt dran.

### 17.4 Zeit- und Abbruch-Budget (User-Entscheidung 2026-04-15)

- **Harte Session-Obergrenze: 12 Stunden.** Danach Session-Ende, auch mit offenen Passes.
- **Pro-Pass-Cap: 2 h aktive Arbeit** (ohne Test-Zeit). Überschreitung → Abbruchregel (Working-Tree auf letzten grünen Commit zurücksetzen, weiter mit nächstem Pass).
- **Pre-existing failed tests:** Einmaliger Baseline-Lauf vor Pass 1. Sind Tests bereits rot, **harter Session-Stopp** mit Befundbericht. Kein Cleanup auf einer kaputten Testbasis, weil sonst keine Regressions-Aussage möglich ist.
- **Zwei aufeinanderfolgende Pass-Abbrüche → Session-Abbruch.** Weitere Versuche wären blind, wenn Umgebung/Testharness strukturell nicht funktioniert. Bericht schreiben, beenden.
- **Bereits committete Passes bleiben stehen.** Jeder grüne Pass ist für sich wertvoll; der Wert des Ein-Commit-pro-Pass-Schemas.

### 17.5 Baseline-Check und Test-Umgebung (User-Entscheidung 2026-04-15)

**Vor Pass 1 einmaliger Baseline-Check:**

1. `Justfile` und `.cargo/config.toml` lesen, um `test-core`/`test-interop`-Aliasse zu verstehen.
2. Python-Umgebung prüfen: `python3 --version`, Importierbarkeit von `vendor/Reticulum/RNS`.
3. `cargo test-core` ausführen (pure Rust).
4. `cargo test-interop` ausführen (inklusive Python-Harness).
5. Befund im Baseline-Bericht festhalten.

**Rot-Definition (strikt gemäß `CLAUDE.md`):** Ein einzelner roter Test beim Baseline → harter Session-Stopp. Keine Cleanup-Arbeit auf kaputter Testbasis.

**Python-Installationen:** `pipx` und Python-venv-Installationen sind ungefragt erlaubt (User-Entscheidung). System-`apt`-Installationen erfordern weiterhin Rückfrage, außer es läuft bereits eine explizite User-Freigabe.

**Sandbox:** Test-Läufe (`cargo test-*`, Python-Harness) dürfen `dangerouslyDisableSandbox` verwenden, weil sie Netzwerk/Fork/Tempfiles nutzen und nicht destruktiv sind. Zustandverändernde Shell-Aktionen (`git push`, `rm -rf`, etc.) bleiben davon unberührt.

### 17.6 `#[allow(dead_code)]`-Pass (User-Entscheidung 2026-04-15)

**Aufnahme in Teil A als neunter Pass** (nach §11.3 `#[ignore]`-Verletzung).

Vorgehen pro Stelle:

1. Datei und Umgebung lesen, um den betroffenen Typ/Fn zu verstehen.
2. Aufrufer-Check mit `ast-grep --lang rust -p '$NAME($$$)'` (für Funktionen) bzw. Feld-Lesen-Suche.
3. Fall-Unterscheidung:
   - **Nur Test-Aufrufer:** Code nach `#[cfg(test)] mod tests`-Block verschieben oder Test-only-Modul anlegen. Allow weg.
   - **0 Aufrufer:** löschen. Allow weg.
   - **Feld wird nur geschrieben, nie gelesen:** löschen, außer es existiert eine nachweisliche Side-Effect-Abhängigkeit (Serde/FFI/Drop).
   - **Nicht-Test-Aufrufer vorhanden, aber Lint feuert wegen Feature-Flag-Kombination:** Ursache prüfen. Oft Fix: Feld/Fn hinter denselben `#[cfg(...)]` packen wie seine Aufrufer.
4. **5-Minuten-Regel ("im Zweifel lassen"):** Wenn binnen 5 Min nicht klar ist, dass die Stelle gefahrlos weg kann, nicht anfassen. Im Abschlussbericht als "gelb" markieren mit Kurzbegründung, Allow bleibt stehen.
5. Pro Einzelfix verifizieren: `cargo check --all-features --all-targets`, `cargo clippy`, `cargo test-core`. Interop-Tests am Ende des gesamten Passes — einzeln nach 30 Fixes zu teuer.

Pass-Ende: ein Commit, Bericht mit Stellen-Liste (weg / umstrukturiert / gelb belassen).

---

### Nach-Cleanup-Definition-of-Done

Ein Cleanup-Pass gilt als abgeschlossen, wenn:
1. `cargo fmt` sauber,
2. `cargo clippy --workspace --no-deps --all-targets -- -D warnings` sauber (inkl. der zwei aktuellen Errors in 1.1),
3. `cargo test-core` + `cargo test-interop` grün,
4. Diff wurde vom User gesichtet.

## 8. Tests

| # | Status | Größe | Thema | Notiz |
|---|--------|-------|-------|-------|
| 8.1 | open | [?] | Test-Harness-Duplikate zwischen `harness.rs` (2063 Zeilen) und anderen Integ-Tests? |
| 8.2 | open | [S] | `eprintln!`-Debug-Ausgaben in Tests — stehen lassen oder auf `tracing`/Log umstellen? |

## 9. Vendor / Submodule / Out-of-scope

| # | Status | Größe | Thema | Notiz |
|---|--------|-------|-------|-------|
| 9.1 | noted | — | `vendor/Reticulum` trägt lokale Patch-Commits (`cebe1bce` = "copy ingress_control and announce_cap on spawned TCP interfaces"). Nur dokumentieren, nicht anfassen. |
| 9.2 | noted | — | **`reticulum-ffi/` ist Out-of-scope** (User-Entscheidung 2026-04-15): Crate ist verwaist, ungepflegt, Stub. Wird in Zukunft separat angegangen. Keine Kommentar-Sweeps, keine `#[allow]`-Tilgung, keine Machete-Fixes, keine Test-Konsolidierung in diesem Crate. Cargo-Machete-Findings für `reticulum-ffi` (`libc`, `reticulum-std` unused) werden nicht bearbeitet, ggf. in `[package.metadata.cargo-machete]` mit `ignored` + Kommentar "stub crate" eingetragen, damit spätere Läufe nicht darauf hinweisen. Das `#[ignore = "FFI crate is outdated …"]` in `reticulum-ffi/tests/ffi_c_tests.rs:30` bleibt vorerst stehen — ist konsistent mit dem Crate-Status. |

## 10. Neue Einträge (während Diskussion)

<!-- Neue Punkte hier anhängen. -->

---

## Methodik

1. Discovery-Phase: Liste mit dem User abstimmen, Ergänzungen/Streichungen aufnehmen.
2. Abarbeitung nach Aufwand: alle **[S]** zuerst, dann **[M]**, **[L]** nur nach expliziter Einzelfreigabe.
3. Nach jedem Batch: `cargo test-core` + `cargo test-interop` (gemäß `CLAUDE.md`). Rot = stoppen.
4. Funktionalität bleibt unangetastet — bei Unsicherheit lieber offen lassen und diskutieren.
