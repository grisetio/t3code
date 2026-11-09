import type { PendingElevationRequest } from "@t3tools/client-runtime/state/elevation";
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
  /**
   * The request Settings raised and answers itself, such as adding or removing this browser: it
   * gets no notice and no card, so it isn't answered twice.
   */
  readonly claimed: ((entry: PendingElevationRequest) => boolean) | null;
  readonly claim: (matches: ((entry: PendingElevationRequest) => boolean) | null) => void;
  /**
   * The machine a card's "Set up this browser" asked Settings to set this device up on. Not in the
   * URL: Settings remounts its page when the search changes, and a reload shouldn't start it again.
   */
  readonly setupRequested: EnvironmentId | null;
  readonly requestSetup: (environmentId: EnvironmentId | null) => void;
  readonly reveal: (target: ElevationSidebarTarget) => void;
  readonly clearHighlight: () => void;
  readonly setListOnScreen: (onScreen: boolean) => void;
}

export const useElevationSidebarStore = create<ElevationSidebarState>()((set) => ({
  highlight: null,
  listOnScreen: false,
  claimed: null,
  claim: (claimed) => set({ claimed }),
  setupRequested: null,
  requestSetup: (setupRequested) => set({ setupRequested }),
  reveal: (target) => set({ highlight: target }),
  clearHighlight: () => set({ highlight: null }),
  setListOnScreen: (listOnScreen) => set({ listOnScreen }),
}));
