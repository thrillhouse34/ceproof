/**
 * Content assembly for M2's document renderers: turns a computed gap
 * checklist + the CRA structure data + an optional ceproof.config into the
 * structured, renderer-agnostic content for the Annex VII technical
 * documentation pack and the Annex V Declaration of Conformity draft.
 *
 * Deliberately separate from src/report/html.ts / pdf.ts: this module owns
 * WHAT each section says (the CRA-domain logic — which items compose from
 * which other items, what "no answer yet" looks like); html.ts/pdf.ts own
 * HOW it's laid out (typography, page breaks, print CSS). Neither renderer
 * should need to know about annex7.7's Annex-V-composition special case —
 * by the time content reaches them, it's already a flat list of sections.
 */
import type { CraStructureItem } from '../cra/types';
import type { GapChecklistItem, GapStatus } from '../gap/types';
import type { CeproofConfig } from '../config/types';
import type { ProvenanceInfo } from './provenance';

export interface ReportSection {
  id: string;
  requirementSummary: string;
  citation: string;
  status: GapStatus;
  /** Human-readable paragraphs/lines. Empty iff isOpenItem is true. */
  body: string[];
  /** True iff this item has no real content yet (NEEDS-HUMAN-INPUT with nothing supplied). */
  isOpenItem: boolean;
  /** True only for annex7.7 when its content was composed from the answered Annex V items rather than answered directly. */
  composedFromAnnexV?: boolean;
}

export interface AnnexPackContent {
  instrument: 'annexVII' | 'annexV';
  title: string;
  projectName: string;
  provenance: ProvenanceInfo;
  sections: ReportSection[];
  /** Count of sections with isOpenItem true, surfaced once so renderers don't have to recompute it. */
  openItemCount: number;
}

const TITLES = {
  annexVII: 'Annex VII — Technical Documentation',
  annexV: 'Annex V — EU Declaration of Conformity',
} as const;

function byId<T extends { id: string }>(items: T[]): Map<string, T> {
  return new Map(items.map((item) => [item.id, item]));
}

/**
 * Resolves ONE item's renderable content, independent of which pack it ends
 * up in. Shared by both computeAnnexViiPackContent and
 * computeAnnexVDocContent, and reused directly (not re-derived) by
 * annex7.7's Annex-V composition below — the composed section must show
 * exactly what a standalone Annex V section would have shown, never a
 * second, possibly-divergent rendering of the same underlying answer.
 */
function contentForItem(
  item: CraStructureItem,
  gapItem: GapChecklistItem,
  config: CeproofConfig | null | undefined
): { body: string[]; isOpenItem: boolean } {
  if (item.derivability === 'boilerplate') {
    // Always DERIVED (see gapEngine.ts) — item.boilerplateText IS the content.
    return { body: [item.boilerplateText ?? ''], isOpenItem: false };
  }

  if (item.derivability === 'human-required') {
    if (gapItem.status === 'DERIVED') {
      const answer = config?.answers?.[item.id];
      // gapEngine only marks a human-required item DERIVED when a non-empty
      // config answer exists, so `answer` should always be present here —
      // but never assume; an empty body would silently look like real
      // content, so fall back to treating it as an open item if it's ever
      // missing (a data-consistency bug elsewhere, not something to paper over).
      if (answer) return { body: [answer], isOpenItem: false };
    }
    return { body: [], isOpenItem: true };
  }

  // derivability is 'derivable' or 'partial': content comes from scan evidence.
  const body = gapItem.evidence.map((e) => `Scan evidence: ${e}`);
  if (gapItem.status === 'PARTIAL') {
    body.push(
      'This item is only partially supported by automated scan evidence — review and supplement before submission.'
    );
  }
  return { body, isOpenItem: false };
}

function annexVPointLabel(id: string): string {
  const m = id.match(/^annex5\.(\d+)$/);
  return m ? `Annex V point ${m[1]}` : id;
}

/**
 * annex7.7 ("a copy of the EU declaration of conformity") is, substantively,
 * exactly what the Annex V items already collect — see the M2 brief's
 * "decision #2". If every Annex V item currently resolves DERIVED (whether
 * via a config answer or the annex5.3 boilerplate class), compose this
 * section from them directly rather than asking the user to answer it a
 * second time. Falls back to a direct config answer, then to an honest open
 * item, in that order — never silently drops to "open item" while a usable
 * answer exists.
 */
function composeAnnex77(
  annexVItems: CraStructureItem[],
  gapById: Map<string, GapChecklistItem>,
  config: CeproofConfig | null | undefined
): { body: string[]; isOpenItem: boolean; composedFromAnnexV: boolean } {
  const allAnnexVDerived = annexVItems.every((v) => gapById.get(v.id)?.status === 'DERIVED');

  if (allAnnexVDerived) {
    const body = annexVItems.map((v) => {
      const gapV = gapById.get(v.id)!;
      const content = contentForItem(v, gapV, config);
      return `${annexVPointLabel(v.id)} (${v.requirementSummary}): ${content.body.join(' ')}`;
    });
    return { body, isOpenItem: false, composedFromAnnexV: true };
  }

  const directAnswer = config?.answers?.['annex7.7'];
  if (directAnswer) {
    return { body: [directAnswer], isOpenItem: false, composedFromAnnexV: false };
  }

  return { body: [], isOpenItem: true, composedFromAnnexV: false };
}

function buildSections(
  items: CraStructureItem[],
  gapById: Map<string, GapChecklistItem>,
  config: CeproofConfig | null | undefined,
  annexVItems: CraStructureItem[]
): ReportSection[] {
  return items.map((item) => {
    const gapItem = gapById.get(item.id);
    if (!gapItem) {
      throw new Error(`annexContent: no gap-checklist entry found for CRA structure item "${item.id}"`);
    }

    if (item.id === 'annex7.7') {
      const composed = composeAnnex77(annexVItems, gapById, config);
      return {
        id: item.id,
        requirementSummary: item.requirementSummary,
        citation: item.citation,
        status: composed.isOpenItem ? gapItem.status : 'DERIVED',
        body: composed.body,
        isOpenItem: composed.isOpenItem,
        composedFromAnnexV: composed.composedFromAnnexV,
      };
    }

    const { body, isOpenItem } = contentForItem(item, gapItem, config);
    return {
      id: item.id,
      requirementSummary: item.requirementSummary,
      citation: item.citation,
      status: gapItem.status,
      body,
      isOpenItem,
    };
  });
}

function computePackContent(
  instrument: 'annexVII' | 'annexV',
  craStructureItems: CraStructureItem[],
  gapChecklist: GapChecklistItem[],
  config: CeproofConfig | null | undefined,
  provenance: ProvenanceInfo,
  projectName: string
): AnnexPackContent {
  const gapById = byId(gapChecklist);
  const items = craStructureItems.filter((i) => i.instrument === instrument);
  const annexVItems = craStructureItems.filter((i) => i.instrument === 'annexV');

  const sections = buildSections(items, gapById, config, annexVItems);

  return {
    instrument,
    title: TITLES[instrument],
    projectName,
    provenance,
    sections,
    openItemCount: sections.filter((s) => s.isOpenItem).length,
  };
}

export function computeAnnexViiPackContent(
  craStructureItems: CraStructureItem[],
  gapChecklist: GapChecklistItem[],
  config: CeproofConfig | null | undefined,
  provenance: ProvenanceInfo,
  projectName: string
): AnnexPackContent {
  return computePackContent('annexVII', craStructureItems, gapChecklist, config, provenance, projectName);
}

export function computeAnnexVDocContent(
  craStructureItems: CraStructureItem[],
  gapChecklist: GapChecklistItem[],
  config: CeproofConfig | null | undefined,
  provenance: ProvenanceInfo,
  projectName: string
): AnnexPackContent {
  return computePackContent('annexV', craStructureItems, gapChecklist, config, provenance, projectName);
}
