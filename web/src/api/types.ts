// Strong-typed DTOs strictly aligned with platform/service/api/workbench/openapi.json.

export type DomainId = "A" | "B" | "C";

export type Role = "ADMIN" | "BUYER" | "AUDITOR";

export type ActionName =
  | "managePurchasingAuthority"
  | "procure"
  | "auditDecisions";

export type AuthorizationMode = "RESOURCE_PREAUTHORIZED" | "BUYER_MANDATE";

export type ProductId = "urn:grad:product:P1" | "urn:grad:product:P2";

export interface ErrorEnvelope {
  requestId: string;
  code: string;
  decisionId: string | null;
  message: string;
}

export interface ReadyResponse {
  domainId: DomainId;
  ready: true;
}

export interface LoginInput {
  username: string;
  password: string;
}

export interface Session {
  domainId: DomainId;
  subjectId: string;
  role: Role;
  actions: ActionName[];
  csrfToken: string;
}

export interface PurchasingAuthority {
  domainId: DomainId;
  expectedRevision: number;
  purchasingAuthority: string | null;
  eligibleServiceIds: string[];
}

export interface SetPurchasingAuthorityInput {
  expectedRevision: number;
  purchasingAuthority: string | null;
}

export type OperationStatus = "PENDING" | "CONFIRMED" | "FAILED";

export interface Operation {
  operationId: string;
  operationKey: string;
  method: string;
  status: OperationStatus;
  stage: string;
  txId: string | null;
  validationCode: string | null;
  failureCode: string | null;
  blockNumber: number | null;
  blockHash?: string;
  transactionIndex: number | null;
  observedPeer: string | null;
  delivered: boolean;
}

export interface ChatInput {
  message: string;
  draftId?: string;
}

export interface Draft {
  draftId: string;
  version: number;
  productId: ProductId | string;
  quantity: number;
  mode: AuthorizationMode;
  maxAmountMinor: number;
  expiresAt: number;
  delegateDid: string;
  description: string;
}

export interface DraftEdit {
  draftId?: string;
  version: number;
  productId: ProductId | string;
  quantity: number;
  mode: AuthorizationMode;
  maxAmountMinor: number;
  expiresAt: number;
  delegateDid: string;
  description: string;
}

export interface DraftVersionInput {
  version: number;
}

export interface ChatResult {
  reply: string;
  draft: Draft;
}

export type RunStage = "REGISTER_TASK" | "DELIVER_G0" | "DELIVER_G1" | "EXECUTE";

export type RunStatus =
  | "PENDING"
  | "FAILED"
  | "MODEL_STOPPED"
  | "GATEWAY_DENIED"
  | "OUTCOME_UNKNOWN"
  | "DECIDED";

export interface RunStep {
  stage: string;
  status: string;
  operationId?: string;
  txId?: string;
  validationCode?: string;
  code?: string;
  grantId?: string;
  at: number;
}

export interface ToolTrace {
  step: number;
  toolName: string;
  arguments?: Record<string, unknown>;
  output?: Record<string, unknown>;
  isError: boolean;
  durationMs: number;
}

export interface Run {
  runId: string;
  taskId: string;
  draftId: string;
  stage: RunStage;
  status: RunStatus;
  confirmedAt: number;
  task: Draft;
  steps: RunStep[];
  traces: ToolTrace[] | null;
  grantRevision?: number;
  grantStatus?: string;
  allowedActions?: string[];
}

export interface RunListResponse {
  runs: Run[] | null;
}

export interface IdentityEvidence {
  did: string;
  domainId?: DomainId;
  issuerDid?: string;
  kind: string;
  status: string;
  keyVersion: number;
  certificationId?: string;
  certificationDigest?: string;
  decisionId: string;
}

export interface DisclosureEvidence {
  subjectDid: string;
  issuerDid: string;
  credentialId: string;
  subjectKeyVersion: number;
  issuerKeyVersion: number;
  disclosed: {
    domain?: string;
    role?: string;
  };
  status: string;
  decisionId: string;
}

export interface DelegationEvidence {
  grantId: string;
  parentId?: string;
  rootId: string;
  mode: AuthorizationMode;
  issuerDid: string;
  granteeDid: string;
  status: string;
  revision: number;
  maxAmountMinor?: number;
  remainingDepth: number;
  nbf: number;
  exp: number;
  decisionId?: string;
}

export interface Quote {
  quoteId: string;
  taskId: string;
  actor: string;
  supplierId: string;
  productId: string;
  quantity: number;
  currency: string;
  unitPriceMinor: number;
  totalAmountMinor: number;
  issuedAt: number;
  validUntil: number;
}

export interface Order {
  orderId: string;
  quoteId: string;
  taskId: string;
  actor: string;
  supplierId: string;
  productId: string;
  quantity: number;
  currency: string;
  totalAmountMinor: number;
  idempotencyKey: string;
  status: string;
  createdAt: number;
}

export interface PurchaseEvidence {
  taskId: string;
  productId: string;
  quantity: number;
  quotes: Quote[];
  orders: Order[];
}

export interface DecisionSummary {
  decisionId?: string;
  requestId?: string;
  probeTxId?: string;
  action: string;
  outcome: string;
  code: string;
  quoteId?: string;
  orderId?: string;
  failedObjectId?: string;
  blockNumber: number;
  blockHash: string;
  policyDigest: string;
  contextVersion: number;
  probeDeadline: number;
  decisionAt: number;
}

export interface RunEvidence {
  identity: IdentityEvidence[];
  disclosures: DisclosureEvidence[];
  delegations: DelegationEvidence[];
  purchase: PurchaseEvidence;
  decisions: DecisionSummary[];
}

export interface Decision {
  stateSource: string;
  revision: number | null;
  stateReadAt: string | null;
  stateRechecks: number;
  deploymentId: string;
  decisionId: string;
  requestId: string;
  challengeId: string;
  actor: string;
  taskId: string;
  action: string;
  idempotencyKey: string;
  outcome: string;
  code: string;
  reason?: string;
  quoteId?: string;
  orderId?: string;
  blockNumber: number | null;
  blockHash: string | null;
  revocationEpoch: number | null;
  probeTxId: string | null;
  probeBlock: number | null;
  probeSentAt: number | null;
  probeDeadline: number | null;
  probeSentAtNs?: number | null;
  probeDeadlineNs?: number | null;
  probeSentMonoNs: number | null;
  probeDeadlineMonoNs: number | null;
  probeCheckedMonoNs?: number | null;
  decisionAt: number;
  decisionAtNs?: number;
  rootDid: string;
  rootKeyVersion: number;
  domainId?: string;
  certificationId?: string;
  certificationDigest?: string;
  domainRevision: number;
  identityIssuer?: string;
  policyDigest: string;
  contextVersion: number;
  contextRiskLevel: string;
  contextObservedAt: number;
  contextAccessDeadline: number;
  effectiveDeadline: number;
  grantPath: string[] | null;
  failedObjectId?: string;
}
