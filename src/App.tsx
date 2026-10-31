import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open, save, ask } from '@tauri-apps/plugin-dialog';
import { v4 as uuidv4 } from 'uuid';
import { VaultPayloadMasked } from './types';
import { useAutoLock } from './useAutoLock';
import { listen } from '@tauri-apps/api/event';

const theme = {
  bg: '#f4f4f5',          // Fond de l'application (Gris perle tres doux)
  surface: '#ffffff',     // Fond des panneaux
  text: '#18181b',        // Texte principal (Presque noir)
  textMuted: '#71717a',   // Texte secondaire (Gris neutre)
  border: '#e4e4e7',      // Lignes de separation ultra-fines
  borderFocus: '#a1a1aa', // Lignes au survol ou focus
  primary: '#18181b',     // Boutons principaux
  action: '#2563eb',      // Bleu professionnel pour les actions positives
  danger: '#dc2626',      // Rouge alerte
  warningBg: '#fffbeb',   // Fond info
  warningText: '#b45309', // Texte info
  editBg: '#fafafa',      // Fond tres leger pour le mode edition
};

const styles = {
  appWrapper: { minHeight: '100vh', backgroundColor: theme.bg, padding: '40px 20px', fontFamily: 'Inter, system-ui, -apple-system, sans-serif', color: theme.text, display: 'flex', flexDirection: 'column' as const, alignItems: 'center' },
  container: { width: '100%', maxWidth: '760px' },

  // Panneaux et Listes
  panel: { backgroundColor: theme.surface, borderRadius: '12px', boxShadow: '0 1px 3px rgba(0, 0, 0, 0.05), 0 10px 15px -3px rgba(0, 0, 0, 0.02)', border: `1px solid ${theme.border}`, overflow: 'hidden' },
  listHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '24px 32px', borderBottom: `1px solid ${theme.border}` },
  listItem: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px 32px', borderBottom: `1px solid ${theme.border}`, transition: 'background-color 0.15s ease' },
  editItem: { padding: '24px 32px', backgroundColor: theme.editBg, borderBottom: `1px solid ${theme.border}`, borderLeft: `3px solid ${theme.action}` },

  // Typographie
  h1: { margin: 0, fontSize: '20px', fontWeight: 600, letterSpacing: '-0.02em', color: theme.text },
  h2: { margin: 0, fontSize: '16px', fontWeight: 600, color: theme.text },
  entryTitle: { margin: 0, fontSize: '15px', fontWeight: 500, color: theme.text },
  entrySubtitle: { margin: '4px 0 0 0', fontSize: '13px', color: theme.textMuted },

  // Formulaires
  formGroup: { marginBottom: '16px' },
  label: { display: 'block', fontSize: '12px', fontWeight: 500, marginBottom: '6px', color: theme.textMuted, textTransform: 'uppercase' as const, letterSpacing: '0.05em' },
  inputRow: { display: 'flex', gap: '8px' },
  input: { flex: 1, padding: '10px 14px', fontSize: '14px', borderRadius: '8px', border: `1px solid ${theme.border}`, outline: 'none', backgroundColor: theme.surface, color: theme.text, transition: 'border-color 0.2s' },
  infoBox: { padding: '12px 16px', backgroundColor: theme.warningBg, color: theme.warningText, borderRadius: '8px', fontSize: '13px', display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '20px' },

  // Boutons Modernes
  btnPrimary: { padding: '10px 18px', backgroundColor: theme.primary, color: 'white', border: 'none', borderRadius: '8px', fontSize: '14px', fontWeight: 500, cursor: 'pointer' },
  btnSecondary: { padding: '10px 18px', backgroundColor: theme.surface, color: theme.text, border: `1px solid ${theme.border}`, borderRadius: '8px', fontSize: '14px', fontWeight: 500, cursor: 'pointer' },
  btnGhost: { padding: '6px 10px', backgroundColor: 'transparent', color: theme.textMuted, border: 'none', fontSize: '13px', fontWeight: 500, cursor: 'pointer', transition: 'color 0.2s' },
  btnGhostAction: { padding: '6px 10px', backgroundColor: 'transparent', color: theme.action, border: 'none', fontSize: '13px', fontWeight: 500, cursor: 'pointer' },
  btnGhostDanger: { padding: '6px 10px', backgroundColor: 'transparent', color: theme.danger, border: 'none', fontSize: '13px', fontWeight: 500, cursor: 'pointer' },
};

function CreateVaultForm({ onCancel }: { onCancel: () => void }) {
  const [error, setError] = useState('');
  const [newVaultPath, setNewVaultPath] = useState('');
  const [newUsbPath, setNewUsbPath] = useState('');

  const selectPath = async (type: 'vault' | 'usb') => {
    const filters = type === 'vault' ? [{ name: 'Vault', extensions: ['vault'] }] : [{ name: 'Clé', extensions: ['bin'] }];
    const title = type === 'vault' ? "Emplacement du coffre" : "Emplacement de la clé USB";
    const path = await save({ title, filters });
    if (path) type === 'vault' ? setNewVaultPath(path) : setNewUsbPath(path);
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault(); setError('');
    if (!newVaultPath || !newUsbPath) return setError("Les deux emplacements sont requis.");

    try {
      await invoke('create_vault', { vaultPath: newVaultPath, usbKeyPath: newUsbPath });
      localStorage.setItem('savedVaultPath', newVaultPath);
      localStorage.setItem('savedUsbPath', newUsbPath);
      window.location.reload();
    } catch (err) { setError(String(err)); }
  };

  return (
    <div style={{ ...styles.panel, padding: '32px' }}>
      <h2 style={{ ...styles.h1, marginBottom: '24px' }}>Initialisation du Coffre</h2>
      <form onSubmit={handleCreate}>
        <div style={styles.formGroup}>
          <label style={styles.label}>Fichier de stockage (.vault)</label>
          <div style={styles.inputRow}>
            <input type="text" value={newVaultPath} readOnly style={styles.input} placeholder="Aucun fichier sélectionné" />
            <button type="button" onClick={() => selectPath('vault')} style={styles.btnSecondary}>Parcourir</button>
          </div>
        </div>
        <div style={styles.formGroup}>
          <label style={styles.label}>Clé de déchiffrement physique (.bin)</label>
          <div style={styles.inputRow}>
            <input type="text" value={newUsbPath} readOnly style={styles.input} placeholder="Aucun fichier sélectionné" />
            <button type="button" onClick={() => selectPath('usb')} style={styles.btnSecondary}>Parcourir</button>
          </div>
        </div>

        <div style={styles.infoBox}>
          <span>ℹ️</span> Les saisies sensibles (mot de passe maître, entropie) seront isolées dans un processus console natif (anti-keylogging).
        </div>

        <button type="submit" style={{ ...styles.btnPrimary, width: '100%' }}>Initialiser le stockage</button>
        <button type="button" onClick={onCancel} style={{ ...styles.btnGhost, width: '100%', marginTop: '12px' }}>Annuler et retourner</button>
      </form>
      {error && <div style={{ color: theme.danger, fontSize: '13px', marginTop: '16px', textAlign: 'center' }}>{error}</div>}
    </div>
  );
}

function RecoverUsbForm({ onCancel }: { onCancel: () => void }) {
  const [newUsbPath, setNewUsbPath] = useState('');
  const [error, setError] = useState('');

  const handleRecover = async (e: React.FormEvent) => {
    e.preventDefault(); setError('');
    if (!newUsbPath) return setError("Veuillez choisir un emplacement.");

    try {
      await invoke('recover_usb_key', { usbKeyPath: newUsbPath });
      localStorage.setItem('savedUsbPath', newUsbPath);
      window.location.reload();
    } catch (err) { setError(String(err)); }
  };

  return (
    <div style={{ ...styles.panel, padding: '32px' }}>
      <h2 style={{ ...styles.h1, marginBottom: '24px' }}>Restauration d'urgence</h2>
      <form onSubmit={handleRecover}>
        <div style={styles.formGroup}>
          <label style={styles.label}>Nouvelle clé USB (.bin)</label>
          <div style={styles.inputRow}>
            <input type="text" value={newUsbPath} readOnly style={styles.input} placeholder="Où recréer la clé ?" />
            <button type="button" onClick={async () => { const p = await save({ filters: [{ name: 'Clé', extensions: ['bin'] }] }); if (p) setNewUsbPath(p); }} style={styles.btnSecondary}>Parcourir</button>
          </div>
        </div>

        <div style={styles.infoBox}>
          <span>ℹ️</span> La saisie de la phrase mnémonique s'effectuera dans un sous-système protégé.
        </div>

        <button type="submit" style={{ ...styles.btnPrimary, width: '100%', backgroundColor: theme.action }}>Saisir la phrase (Terminal)</button>
        <button type="button" onClick={onCancel} style={{ ...styles.btnGhost, width: '100%', marginTop: '12px' }}>Annuler</button>
      </form>
      {error && <div style={{ color: theme.danger, fontSize: '13px', marginTop: '16px', textAlign: 'center' }}>{error}</div>}
    </div>
  );
}

// RATIONALE ARCHITECTURAL : ZERO-KNOWLEDGE FRONTEND
// L'interface React opere sous une politique de "Zero-Trust" vis-à-vis du Backend.
// Le type `VaultPayloadMasked` purge les secrets en clair (mots de passe, notes) avant serialisation vers la WebView.
// Le DOM ne manipule que des etats booleens (ex: `has_password: true`) pour le rendu conditionnel.
// En cas de compromission du moteur V8/WebKit, aucun materiel cryptographique n'est extractible de la heap JS.

function App() {
  const [vaultData, setVaultData] = useState<VaultPayloadMasked | null>(null);
  const [view, setView] = useState<'unlock' | 'create' | 'recover'>('unlock');

  const [vaultPath, setVaultPath] = useState('');
  const [usbPath, setUsbPath] = useState('');
  const [error, setError] = useState('');

  const [editingEntryId, setEditingEntryId] = useState<string | null>(null);
  const [editFormData, setEditFormData] = useState({ title: '', username: '', url: '' });

  // État du pont IPC (Native Messaging)
  const [profiles, setProfiles] = useState<{ name: string, path: string }[]>([]);
  const [selectedProfile, setSelectedProfile] = useState<string>('');
  const [installStatus, setInstallStatus] = useState<string>('');

  useAutoLock(vaultData !== null);

  useEffect(() => {
    const unlisten = listen('vault-locked', () => {
      setVaultData(null);
    });
    return () => { unlisten.then(f => f()); };
  }, []);

  // Chargement automatique des profils LibreWolf à l'ouverture du coffre
  useEffect(() => {
    if (vaultData) {
      invoke<{ name: string, path: string }[]>('get_browser_profiles')
        .then(profs => {
          setProfiles(profs);
          if (profs.length > 0) setSelectedProfile(profs[0].path);
        })
        .catch(console.error);
    }
  }, [vaultData]);

  const selectPath = async (type: 'vault' | 'usb') => {
    const filters = type === 'vault' ? [{ name: 'Vault', extensions: ['vault'] }] : [{ name: 'Clé', extensions: ['bin'] }];
    const path = await open({ filters });
    if (path) {
      type === 'vault' ? setVaultPath(path) : setUsbPath(path);
      localStorage.setItem(type === 'vault' ? 'savedVaultPath' : 'savedUsbPath', path);
    }
  };

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault(); setError('');
    if (!vaultPath || !usbPath) return setError("Sélectionnez vos fichiers de sécurité.");
    try {
      const data: VaultPayloadMasked = await invoke('unlock_vault', { vaultPath, usbKeyPath: usbPath });
      setVaultData(data);
    } catch (err) { setError(String(err)); }
  };

  const handleAction = async (action: () => Promise<void>) => {
    try { await action(); } catch (err) { alert(err); }
  };

  const handleInstallHook = async () => {
    if (!selectedProfile) return;
    setInstallStatus('Provisioning du profil en cours...');
    try {
      await invoke('install_browser_hook', { profilePath: selectedProfile });
      setInstallStatus('✅ Succès : Hôte IPC configuré et extension provisionnée.');
      setTimeout(() => setInstallStatus(''), 4000); // Fait disparaitre le message apres 4s
    } catch (err) {
      setInstallStatus('❌ Erreur : ' + String(err));
    }
  };

  // Fonction de nettoyage (Anti-Forensique)
  const handleUninstallHook = async () => {
    if (!selectedProfile) return;
    setInstallStatus('Révocation de la configuration...');
    try {
      await invoke('uninstall_browser_hook', { profilePath: selectedProfile });
      setInstallStatus('✅ Succès : Hôte IPC révoqué et profil restauré.');
      setTimeout(() => setInstallStatus(''), 4000);
    } catch (err) {
      setInstallStatus('❌ Erreur : ' + String(err));
    }
  };
  {/* 
   * CONSTRAINT: Le `overflow: hidden` global combine au Window Manager backend (HWND)
   * empeche le redimensionnement arbitraire et verrouille les frontieres de rendu de la WebView.
   */}
  return (
    <>
      <style>{`
        html, body {
          margin: 0;
          padding: 0;
          overflow: hidden !important; 
          width: 100vw;
          height: 100vh;
          background-color: ${theme.bg};
        }
        * { box-sizing: border-box; }
      `}</style>

      {vaultData ? (
        <div style={styles.appWrapper}>
          <div style={styles.container}>

            <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ width: '32px', height: '32px', backgroundColor: theme.primary, borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white', fontSize: '14px' }}>
                  B
                </div>
                <div>
                  <h1 style={{ margin: 0, fontSize: '18px', fontWeight: 600, color: theme.text }}>Bleax Vault</h1>
                  <div style={{ fontSize: '12px', color: theme.textMuted }}>Air-Gap Protégé</div>
                </div>
              </div>
              <button onClick={async () => { await invoke('lock_vault'); setVaultData(null); }} style={{ ...styles.btnSecondary, borderColor: theme.danger, color: theme.danger }}>
                Verrouiller
              </button>
            </header>

            <div style={{ maxHeight: 'calc(100vh - 120px)', overflowY: 'auto', paddingBottom: '20px' }}>

              <div style={{ ...styles.panel, marginBottom: '24px' }}>
                <div style={styles.listHeader}>
                  <h2 style={styles.h2}>Éléments ({vaultData.entries.length})</h2>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button onClick={() => handleAction(async () => setVaultData(await invoke('add_login', { vaultPath, id: uuidv4(), title: "Nouveau compte", username: "", url: "" })))} style={styles.btnSecondary}>
                      + Identifiant
                    </button>
                    <button onClick={() => handleAction(async () => setVaultData(await invoke('add_note', { vaultPath, id: uuidv4(), title: "Nouvelle Note" })))} style={styles.btnSecondary}>
                      + Note
                    </button>
                  </div>
                </div>

                <div style={{ backgroundColor: theme.surface }}>
                  {vaultData.entries.length === 0 ? (
                    <div style={{ padding: '60px 0', textAlign: 'center', color: theme.textMuted, fontSize: '14px' }}>
                      Votre coffre est vide. Créez un élément pour commencer.
                    </div>
                  ) : (
                    vaultData.entries.map((entry, index) => {
                      const isLast = index === vaultData.entries.length - 1;
                      const borderStyle = isLast ? 'none' : `1px solid ${theme.border}`;

                      if (editingEntryId === entry.id) {
                        return (
                          <div key={entry.id} style={{ ...styles.editItem, borderBottom: borderStyle }}>
                            <div style={{ display: 'flex', gap: '16px', marginBottom: '16px' }}>
                              <div style={{ flex: 1 }}>
                                <label style={styles.label}>Titre</label>
                                <input type="text" value={editFormData.title} onChange={(e) => setEditFormData({ ...editFormData, title: e.target.value })} style={styles.input} />
                              </div>
                              {entry.entry_type === "Login" && (
                                <div style={{ flex: 1 }}>
                                  <label style={styles.label}>Nom d'utilisateur</label>
                                  <input type="text" value={editFormData.username} onChange={(e) => setEditFormData({ ...editFormData, username: e.target.value })} style={styles.input} />
                                </div>
                              )}
                            </div>
                            {entry.entry_type === "Login" && (
                              <div style={{ marginBottom: '24px' }}>
                                <label style={styles.label}>URL du site web</label>
                                <input type="text" value={editFormData.url} onChange={(e) => setEditFormData({ ...editFormData, url: e.target.value })} style={styles.input} placeholder="https://" />
                              </div>
                            )}
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <button onClick={() => handleAction(async () => { setVaultData(await invoke('update_secret', { vaultPath, id: entry.id })); })} style={{ ...styles.btnSecondary, color: theme.warningText }}>
                                Modifier le Secret (Terminal)
                              </button>
                              <div style={{ display: 'flex', gap: '8px' }}>
                                <button onClick={() => setEditingEntryId(null)} style={styles.btnGhost}>Annuler</button>
                                <button onClick={() => handleAction(async () => { setVaultData(await invoke('update_metadata', { vaultPath, id: entry.id, ...editFormData })); setEditingEntryId(null); })} style={styles.btnPrimary}>
                                  Enregistrer
                                </button>
                              </div>
                            </div>
                          </div>
                        );
                      }

                      return (
                        <div key={entry.id} style={{ ...styles.listItem, borderBottom: borderStyle }} onMouseEnter={(e) => e.currentTarget.style.backgroundColor = theme.bg} onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}>

                          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                            <div style={{ fontSize: '20px', opacity: 0.8 }}>
                              {entry.entry_type === "Login" ? '🌍' : '📝'}
                            </div>
                            <div>
                              <h3 style={styles.entryTitle}>{entry.title}</h3>
                              <div style={styles.entrySubtitle}>
                                {entry.entry_type === "Login" ? (
                                  <>{entry.url ? entry.url.replace(/^https?:\/\//, '') : "Pas d'URL"} <span style={{ opacity: 0.5, margin: '0 6px' }}>|</span> {entry.username || "Sans identifiant"}</>
                                ) : ("Note sécurisée")}
                              </div>
                            </div>
                          </div>

                          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                            {(entry.has_password || entry.has_note) && (
                              <>
                                <button onClick={() => handleAction(async () => { await invoke('secure_copy_secret', { id: entry.id }); })} style={styles.btnGhostAction}>Copier</button>
                                <button onClick={() => handleAction(async () => await invoke('show_secret', { id: entry.id }))} style={styles.btnGhostAction}>Voir</button>
                                <div style={{ width: '1px', height: '16px', backgroundColor: theme.border, margin: '0 8px' }}></div>
                              </>
                            )}
                            <button onClick={() => handleAction(async () => {
                              const isConfirmed = await ask("Générer un nouveau secret cryptographiquement sûr (20 caractères) ? L'ancien sera écrasé.", { title: "Avertissement", kind: "warning" });
                              if (isConfirmed) {
                                setVaultData(await invoke('generate_and_save_secret', { vaultPath, id: entry.id }));
                              }
                            })} style={styles.btnGhost}>
                              Auto-Gen
                            </button>
                            <button onClick={() => { setEditFormData({ title: entry.title, username: entry.username || '', url: entry.url || '' }); setEditingEntryId(entry.id); }} style={styles.btnGhost}>Éditer</button>
                            <button onClick={() => handleAction(async () => {
                              const isConfirmed = await ask("Supprimer cet élément définitivement ?", { title: "Confirmation", kind: "warning" });
                              if (isConfirmed) {
                                setVaultData(await invoke('delete_entry', { vaultPath, id: entry.id }));
                              }
                            })} style={styles.btnGhostDanger}>
                              Supprimer
                            </button>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>

              <div style={styles.panel}>
                <div style={styles.listHeader}>
                  <h2 style={styles.h2}>Pont IPC Navigateur (Native Messaging)</h2>
                </div>
                <div style={{ padding: '24px 32px' }}>
                  <p style={{ fontSize: '13px', color: theme.textMuted, marginBottom: '20px', lineHeight: '1.5' }}>
                    Le provisioning de l'hôte IPC enregistre le binaire actuel dans le registre système et ajuste les stratégies (user.js) du profil cible pour autoriser la communication chiffrée avec l'extension navigateur. L'exécutable local ne doit pas être déplacé après cette opération.
                  </p>

                  <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                    {profiles.length > 0 ? (
                      <>
                        <select
                          style={{ ...styles.input, flex: 'none', width: '250px' }}
                          value={selectedProfile}
                          onChange={e => setSelectedProfile(e.target.value)}
                        >
                          {profiles.map(p => <option key={p.path} value={p.path}>{p.name}</option>)}
                        </select>
                        <button onClick={handleInstallHook} style={{ ...styles.btnPrimary, backgroundColor: theme.action }}>
                          Configurer l'Hôte IPC
                        </button>

                        <button onClick={handleUninstallHook} style={{ ...styles.btnSecondary, color: theme.danger, borderColor: theme.danger }}>
                          Révoquer l'accès
                        </button>
                      </>
                    ) : (
                      <div style={{ fontSize: '13px', color: theme.warningText }}>Aucun profil Firefox/LibreWolf détecté sur ce système.</div>
                    )}
                  </div>

                  {installStatus && (
                    <div style={{ marginTop: '16px', fontSize: '13px', fontWeight: 500, color: installStatus.includes('✅') ? theme.action : theme.danger }}>
                      {installStatus}
                    </div>
                  )}
                </div>
              </div>

            </div>
          </div>
        </div>
      ) : (

        <div style={{ ...styles.appWrapper, justifyContent: 'center' }}>
          <div style={styles.container}>
            <div style={{ maxWidth: '420px', margin: '0 auto' }}>

              {view === 'create' && <CreateVaultForm onCancel={() => setView('unlock')} />}
              {view === 'recover' && <RecoverUsbForm onCancel={() => setView('unlock')} />}

              {view === 'unlock' && (
                <div style={{ ...styles.panel, padding: '40px 32px' }}>
                  <div style={{ textAlign: 'center', marginBottom: '32px' }}>
                    <div style={{ width: '48px', height: '48px', backgroundColor: theme.primary, borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white', fontSize: '20px', margin: '0 auto 16px' }}>
                      B
                    </div>
                    <h1 style={{ ...styles.h1, fontSize: '24px' }}>Bleax Vault</h1>
                    <p style={styles.entrySubtitle}>Cryptographie hors-ligne</p>
                  </div>

                  <form onSubmit={handleUnlock}>
                    <div style={styles.formGroup}>
                      <label style={styles.label}>Fichier de stockage (.vault)</label>
                      <div style={styles.inputRow}>
                        <input type="text" value={vaultPath} readOnly style={styles.input} placeholder="..." />
                        <button type="button" onClick={() => selectPath('vault')} style={styles.btnSecondary}>Ouvrir</button>
                      </div>
                    </div>
                    <div style={styles.formGroup}>
                      <label style={styles.label}>Clé matérielle (.bin)</label>
                      <div style={styles.inputRow}>
                        <input type="text" value={usbPath} readOnly style={styles.input} placeholder="..." />
                        <button type="button" onClick={() => selectPath('usb')} style={styles.btnSecondary}>Ouvrir</button>
                      </div>
                    </div>

                    <button type="submit" style={{ ...styles.btnPrimary, width: '100%', marginTop: '8px' }}>Déchiffrer le coffre (Terminal)</button>
                  </form>

                  <div style={{ marginTop: '32px', paddingTop: '24px', borderTop: `1px solid ${theme.border}`, display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <button onClick={() => setView('create')} style={styles.btnGhost}>Créer un nouveau coffre</button>
                    <button onClick={() => setView('recover')} style={styles.btnGhost}>Clé USB perdue ? (Restauration)</button>
                  </div>

                  {error && <div style={{ color: theme.danger, fontSize: '13px', marginTop: '16px', textAlign: 'center' }}>{error}</div>}
                </div>
              )}

            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default App;