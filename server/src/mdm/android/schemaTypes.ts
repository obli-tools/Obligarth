// =============================================================================
// Form of the AMAPI schemas the server ships (generated from Google's
// discovery document of androidmanagement v1, pinned revision): what the
// validation and the compilation of the Android policies read. Types, formats,
// enumerations and deprecations only: the descriptions stay in the document.
// =============================================================================

export type AmapiSchemaType = 'string' | 'integer' | 'number' | 'boolean' | 'object' | 'array' | 'any';

export interface AmapiSchemaNode {
  type?: AmapiSchemaType;
  /** Another schema of the catalog, by its id. */
  $ref?: string;
  /** int32, int64, double, float, byte, google-datetime, google-duration, google-fieldmask. */
  format?: string;
  enum?: readonly string[];
  /** Values of `enum` the document marks deprecated. */
  deprecatedValues?: readonly string[];
  deprecated?: boolean;
  readOnly?: boolean;
  items?: AmapiSchemaNode;
  properties?: Readonly<Record<string, AmapiSchemaNode>>;
  additionalProperties?: AmapiSchemaNode;
}

export interface AmapiSchemaCatalog {
  /** Revision of the discovery document (YYYYMMDD). */
  revision: string;
  /** SHA-256 of the discovery document the catalog was generated from. */
  sourceSha256: string;
  /** Schema id of the root (Policy). */
  root: string;
  schemas: Readonly<Record<string, AmapiSchemaNode>>;
}
