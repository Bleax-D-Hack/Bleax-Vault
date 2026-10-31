export interface VaultPayloadMasked {
  schema_version: number;
  vault_updated_at: number;
  entries: VaultEntryMasked[];
}

export interface VaultEntryMasked {
  id: string;
  last_modified: number;
  title: string;
  entry_type: "Login" | "SecureNote";
  
  username?: string | null;
  url?: string | null;
  
  has_password: boolean;
  has_note: boolean;
}