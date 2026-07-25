import { describe, it, expect } from 'vitest';
import { getCraStructure } from '../../src/cra/loader';

// Doctrine, non-negotiable: `citation` is the single most legally load-bearing
// string in a document a customer hands to an auditor. tests/cra/
// traceability.test.ts already proves every item's `sourceExcerpt` appears
// SOMEWHERE, verbatim, in its cited `sourceFile` — but it does not prove the
// excerpt is drawn from the CORRECT Annex point, only that the substring
// exists in the file at all. A citation claiming "Annex VII, point 1(b)"
// whose excerpt actually came from a different point (a copy-paste slip
// during hand-authoring, or an off-by-one in the numbering) would still pass
// that test.
//
// This test closes that gap: for every item, an independent ground-truth
// text span — copied by hand directly from the vendored primary source
// (data/sources/celex-02024r2847-20241120-en.txt, Annex V lines 1352-1373,
// Annex VII lines 1381-1420), keyed by CRA item id, NOT derived from
// data/cra-structure.json or from any extraction script — and asserts the
// item's sourceExcerpt falls within its OWN correctly-cited point's span. If
// data-authoring ever pastes the wrong point's text into an item (or the
// regulation's numbering is mis-mapped to an item id), this test fails even
// though traceability.test.ts would still pass.
//
// All 21 items, every time — never sampled. If a future re-extraction adds a
// new item, this test's ground-truth table must be extended by hand, reading
// the real source text again, not copied from the tool under test.

const GROUND_TRUTH_SPANS: Record<string, string> = {
  // Annex V — flat points 1-8 (EU declaration of conformity, Article 28).
  'annex5.1':
    'Name and type and any additional information enabling the unique identification of the product with digital elements',
  'annex5.2': 'Name and address of the manufacturer or its authorised representative',
  'annex5.3': 'A statement that the EU declaration of conformity is issued under the sole responsibility of the provider',
  'annex5.4':
    'Object of the declaration (identification of the product with digital elements allowing traceability, which may include a photograph, where appropriate)',
  'annex5.5':
    'A statement that the object of the declaration described above is in conformity with the relevant Union harmonisation legislation',
  'annex5.6':
    'References to any relevant harmonised standards used or any other common specification or cybersecurity certification in relation to which conformity is declared',
  'annex5.7':
    'Where applicable, the name and number of the notified body, a description of the conformity assessment procedure performed and identification of the certificate issued',
  'annex5.8': 'Additional information:\nSigned for and on behalf of:\n(place and date of issue):\n(name, function) (signature):',

  // Annex VII — content of the technical documentation (Article 31).
  'annex7.1.a': 'its intended purpose;',
  'annex7.1.b': 'versions of software affecting compliance with essential cybersecurity requirements;',
  'annex7.1.c':
    'where the product with digital elements is a hardware product, photographs or illustrations showing external features, marking and internal layout;',
  'annex7.1.d': 'user information and instructions as set out in Annex II;',
  'annex7.2.a':
    'necessary information on the design and development of the product with digital elements, including, where applicable, drawings and schemes and a description of the system architecture explaining how software components build on or feed into each other and integrate into the overall processing;',
  'annex7.2.b':
    'necessary information and specifications of the vulnerability handling processes put in place by the manufacturer, including the software bill of materials, the coordinated vulnerability disclosure policy, evidence of the provision of a contact address for the reporting of the vulnerabilities and a description of the technical solutions chosen for the secure distribution of updates;',
  'annex7.2.c':
    'necessary information and specifications of the production and monitoring processes of the product with digital elements and the validation of those processes;',
  'annex7.3':
    'an assessment of the cybersecurity risks against which the product with digital elements is designed, developed, produced, delivered and maintained pursuant to Article 13, including how the essential cybersecurity requirements set out in Part I of Annex I are applicable;',
  'annex7.4':
    'relevant information that was taken into account to determine the support period pursuant to Article 13(8) of the product with digital elements;',
  'annex7.5':
    'a list of the harmonised standards applied in full or in part the references of which have been published in the\nOfficial Journal of the European Union\n, common specifications as set out in Article 27 of this Regulation or European cybersecurity certification schemes adopted pursuant to Regulation (EU) 2019/881 pursuant to Article 27(8) of this Regulation, and, where those harmonised standards, common specifications or European cybersecurity certification schemes have not been applied, descriptions of the solutions adopted to meet the essential cybersecurity requirements set out in Parts I and II of Annex I, including a list of other relevant technical specifications applied. In the event of partly applied harmonised standards, common specifications or European cybersecurity certification schemes, the technical documentation shall specify the parts which have been applied;',
  'annex7.6':
    'reports of the tests carried out to verify the conformity of the product with digital elements and of the vulnerability handling processes with the applicable essential cybersecurity requirements as set out in Parts I and II of Annex I;',
  'annex7.7': 'a copy of the EU declaration of conformity;',
  'annex7.8':
    'where applicable, the software bill of materials, further to a reasoned request from a market surveillance authority provided that it is necessary in order for that authority to be able to check compliance with the essential cybersecurity requirements set out in Annex I.',
};

// Which Annex/point each id names, independent of data/cra-structure.json's
// own citation text — used to cross-check citation.point-number accuracy,
// not just excerpt containment.
const GROUND_TRUTH_POINT_LABEL: Record<string, string> = {
  'annex5.1': 'point 1',
  'annex5.2': 'point 2',
  'annex5.3': 'point 3',
  'annex5.4': 'point 4',
  'annex5.5': 'point 5',
  'annex5.6': 'point 6',
  'annex5.7': 'point 7',
  'annex5.8': 'point 8',
  'annex7.1.a': 'point 1(a)',
  'annex7.1.b': 'point 1(b)',
  'annex7.1.c': 'point 1(c)',
  'annex7.1.d': 'point 1(d)',
  'annex7.2.a': 'point 2(a)',
  'annex7.2.b': 'point 2(b)',
  'annex7.2.c': 'point 2(c)',
  'annex7.3': 'point 3',
  'annex7.4': 'point 4',
  'annex7.5': 'point 5',
  'annex7.6': 'point 6',
  'annex7.7': 'point 7',
  'annex7.8': 'point 8',
};

describe('CRA structure data — citation accuracy (independent ground truth, not derived from the tool under test)', () => {
  const structure = getCraStructure();

  it('the ground-truth table covers every item currently in cra-structure.json (no drift either direction)', () => {
    const structureIds = new Set(structure.items.map((i) => i.id));
    const groundTruthIds = new Set(Object.keys(GROUND_TRUTH_SPANS));
    expect(
      [...structureIds].sort(),
      'cra-structure.json has an item with no ground-truth entry — extend this test\'s table by hand, reading the real source text',
    ).toEqual([...groundTruthIds].sort());
  });

  it('every sourceExcerpt falls within its OWN correctly-cited point\'s ground-truth span, not just somewhere in the file', () => {
    const failures: string[] = [];
    for (const item of structure.items) {
      const span = GROUND_TRUTH_SPANS[item.id];
      if (span === undefined) {
        failures.push(`${item.id}: no ground-truth span (see the "table covers every item" test above)`);
        continue;
      }
      if (!span.includes(item.sourceExcerpt)) {
        failures.push(
          `${item.id}: sourceExcerpt does NOT fall within its own point's ground-truth span\n` +
            `  excerpt: ${JSON.stringify(item.sourceExcerpt)}\n` +
            `  ground truth span: ${JSON.stringify(span)}`,
        );
      }
    }
    expect(failures, failures.join('\n')).toEqual([]);
  });

  it('every citation names the correct point number for its id, per independent ground truth', () => {
    const failures: string[] = [];
    for (const item of structure.items) {
      const label = GROUND_TRUTH_POINT_LABEL[item.id];
      if (label === undefined) {
        failures.push(`${item.id}: no ground-truth point label`);
        continue;
      }
      if (!item.citation.includes(label)) {
        failures.push(`${item.id}: citation does not contain the expected "${label}" — citation was: ${item.citation}`);
      }
    }
    expect(failures, failures.join('\n')).toEqual([]);
  });
});
