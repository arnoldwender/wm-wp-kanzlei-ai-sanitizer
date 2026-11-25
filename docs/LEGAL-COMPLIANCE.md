# Legal context — WM Kanzlei AI Sanitizer

This file quotes the provisions a law firm meets when it uses an AI service, and says what the plugin does and does not do about them. It gives no legal assessment. Texts retrieved from gesetze-im-internet.de and EUR-Lex on 2026-09-15.

The earlier edition of this file said that sending raw client data to foreign AI servers "constitutes an unauthorized disclosure", that the plugin "completely eliminates this liability by stripping all identifying client secrets", that its logs "prove strict compliance and zero-knowledge transmission" to the bar associations, and that local tokenisation "ensures zero personal data leaves the European sovereign perimeter". None of that is backed: the plugin sends nothing, does not find every identifying value, and its log records only that a replacement ran.

---

## § 203 StGB — Verletzung von Privatgeheimnissen

- Abs. 1 covers, among others (Nr. 3), "Rechtsanwalt, Kammerrechtsbeistand, Patentanwalt, Notar, Verteidiger in einem gesetzlich geordneten Verfahren, Wirtschaftsprüfer, vereidigtem Buchprüfer, Steuerberater, Steuerbevollmächtigten" and (Nr. 1) physicians; whoever discloses a secret without authority "wird mit Freiheitsstrafe bis zu einem Jahr oder mit Geldstrafe bestraft."
- Abs. 3 Satz 2: "Die in den Absätzen 1 und 2 Genannten dürfen fremde Geheimnisse gegenüber sonstigen Personen offenbaren, die an ihrer beruflichen oder dienstlichen Tätigkeit mitwirken, soweit dies für die Inanspruchnahme der Tätigkeit der sonstigen mitwirkenden Personen erforderlich ist; …"
- Abs. 4 Satz 2 Nr. 1: also punishable is who, as a person named in Abs. 1 or 2, "nicht dafür Sorge getragen hat, dass eine sonstige mitwirkende Person, die unbefugt ein fremdes, ihr bei der Ausübung oder bei Gelegenheit ihrer Tätigkeit bekannt gewordenes Geheimnis offenbart, zur Geheimhaltung verpflichtet wurde; …"

## § 43e BRAO — Inanspruchnahme von Dienstleistungen

- Abs. 1: "Der Rechtsanwalt darf Dienstleistern den Zugang zu Tatsachen eröffnen, auf die sich die Verpflichtung zur Verschwiegenheit gemäß § 43a Absatz 2 Satz 1 bezieht, soweit dies für die Inanspruchnahme der Dienstleistung erforderlich ist."
- Abs. 3: "Der Vertrag mit dem Dienstleister bedarf der Textform." It obliges the provider to secrecy, with instruction on the criminal consequences, limits its knowledge to what the contract needs, and settles whether it may engage further persons.
- Abs. 4: for services rendered abroad, access to secrets only "wenn der dort bestehende Schutz der Geheimnisse dem Schutz im Inland vergleichbar ist, es sei denn, dass der Schutz der Geheimnisse dies nicht gebietet."
- Abs. 5: "Bei der Inanspruchnahme von Dienstleistungen, die unmittelbar einem einzelnen Mandat dienen, darf der Rechtsanwalt dem Dienstleister den Zugang zu fremden Geheimnissen nur dann eröffnen, wenn der Mandant darin eingewilligt hat."
- Abs. 8: "Die Vorschriften zum Schutz personenbezogener Daten bleiben unberührt."

## DSGVO

- Art. 4 Nr. 5 defines „Pseudonymisierung“ as processing so that the data "ohne Hinzuziehung zusätzlicher Informationen nicht mehr einer spezifischen betroffenen Person zugeordnet werden können, sofern diese zusätzlichen Informationen gesondert aufbewahrt werden und technischen und organisatorischen Maßnahmen unterliegen, …".
- Erwägungsgrund 26: "Einer Pseudonymisierung unterzogene personenbezogene Daten, die durch Heranziehung zusätzlicher Informationen einer natürlichen Person zugeordnet werden könnten, sollten als Informationen über eine identifizierbare natürliche Person betrachtet werden."
- Transfers to a recipient outside the EU follow Chapter V (Art. 44 ff.).

---

## What the plugin does about it

| Topic | What the code does | What it does not do |
| --- | --- | --- |
| Reducing what a provider sees | Replaces seven types of values with placeholders before your application sends the text | Find names without a title, addresses, dates of birth, most ID numbers, health data; decide what is "erforderlich" in the sense of § 203 Abs. 3 or § 43e Abs. 1 |
| The mapping | Returns it to your application; stores it nowhere | Keep it "gesondert" under technical and organisational measures (Art. 4 Nr. 5) — that is your application's job |
| The provider | Nothing: `/proxy` answers 501 | Choose, contract (§ 43e Abs. 3), check the protection abroad (§ 43e Abs. 4), obtain the client's consent (§ 43e Abs. 5) |
| Evidence | A sealed log row per replacement (types, time), a session record per call | Record what was sent to whom, prove conformity with any provision, issue certificates |

Whether a given use of an AI service is lawful for a given firm and mandate is a question for that firm and its advisers.
