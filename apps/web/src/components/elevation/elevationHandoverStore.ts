import type { RunId } from "@t3tools/contracts";
import { create } from "zustand";

interface ElevationHandover {
  /** `elevationLinkedCommandKey` of the agent's command row the card stands beside, if any. */
  readonly commandKey: string | null;
  readonly runId: RunId | null;
}

interface ElevationHandoverState {
  readonly byCard: ReadonlyMap<string, ElevationHandover>;
  /**
   * Command rows whose request's card is on screen. The timeline keeps them until the card has
   * collapsed, so the card's settled row replaces the command row in one commit.
   */
  readonly commandKeys: ReadonlySet<string>;
  /** Runs with a card on screen: their turn folds only once the card has handed over. */
  readonly runIds: ReadonlySet<RunId>;
  readonly hold: (card: string, handover: ElevationHandover) => void;
  readonly release: (card: string) => void;
}

function withCards(byCard: ReadonlyMap<string, ElevationHandover>) {
  const handovers = [...byCard.values()];
  return {
    byCard,
    commandKeys: new Set(handovers.flatMap(({ commandKey }) => commandKey ?? [])),
    runIds: new Set(handovers.flatMap(({ runId }) => runId ?? [])),
  };
}

/** Thread cards still on screen, from arrival until their settled row has taken their place. */
export const useElevationHandoverStore = create<ElevationHandoverState>()((set, get) => ({
  ...withCards(new Map()),
  hold: (card, handover) => {
    const current = get().byCard.get(card);
    if (current?.commandKey === handover.commandKey && current.runId === handover.runId) return;
    set(withCards(new Map(get().byCard).set(card, handover)));
  },
  release: (card) => {
    if (!get().byCard.has(card)) return;
    const next = new Map(get().byCard);
    next.delete(card);
    set(withCards(next));
  },
}));
