export interface Secret {
  id: string;
  name: string;
  level: number;
  secret_type: string;
  encrypted_value: string;
  tags: string[];
  expiry: string | null;
  url: string | null;
  username: string | null;
  folder: string | null;
  created_at: string;
}

export interface SessionLog {
  id: number;
  session_id: string;
  user_level: number;
  action: string;
  details: string;
  created_at: string;
}
