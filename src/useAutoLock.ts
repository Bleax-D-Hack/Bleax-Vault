import { useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';

export function useAutoLock(isActive: boolean) {
  const lastActivityRef = useRef<number>(Date.now());

  useEffect(() => {
    if (!isActive) return;

    const updateActivity = () => {
      lastActivityRef.current = Date.now();
    };

    window.addEventListener('mousemove', updateActivity);
    window.addEventListener('keydown', updateActivity);
    window.addEventListener('mousedown', updateActivity);
    window.addEventListener('scroll', updateActivity);

    // Stratégie IPC Batching : Pour éviter de surcharger le backend Rust via le pont IPC à chaque mouvement de souris,
    // on évalue l'état local périodiquement. Si une activité est détectée, un unique Keep-Alive est envoyé pour réinitialiser le Watchdog natif.
    const pingInterval = window.setInterval(() => {
      const now = Date.now();
      if (now - lastActivityRef.current < 5000) {
        invoke('ping_activity').catch(() => { });
      }
    }, 5000);

    return () => {
      window.removeEventListener('mousemove', updateActivity);
      window.removeEventListener('keydown', updateActivity);
      window.removeEventListener('mousedown', updateActivity);
      window.removeEventListener('scroll', updateActivity);
      window.clearInterval(pingInterval);
    };
  }, [isActive]);
}