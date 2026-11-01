import type { ElevationRequestId, EnvironmentId } from "@t3tools/contracts";
import { create } from "zustand";

export interface ElevationSidebarTarget {
  readonly environmentId: EnvironmentId;
  readonly requestId: ElevationRequestId;
}

interface ElevationSidebarState {
  /** A request no thread claims, opened from its notice: the sidebar shows it and points at it. */
  readonly highlight: ElevationSidebarTarget | null;
  /** The sidebar's requests section is in view, so notices leave those requests to it. */
  readonly listOnScreen: boolean;
  readonly reveal: (target: ElevationSidebarTarget) => void;
  readonly clearHighlight: () => void;
  readonly setListOnScreen: (onScreen: boolean) => void;
}

export const useElevationSidebarStore = create<ElevationSidebarState>()((set) => ({
  highlight: null,
  listOnScreen: false,
  reveal: (target) => set({ highlight: target }),
  clearHighlight: () => set({ highlight: null }),
  setListOnScreen: (listOnScreen) => set({ listOnScreen }),
}));
