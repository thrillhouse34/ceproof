// Single shared source for "what counts as permissive", used by the resolver
// when choosing the most-permissive branch of an OR expression.
export const PERMISSIVE_IDS = new Set(['MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0', '0BSD', 'Unlicense']);
