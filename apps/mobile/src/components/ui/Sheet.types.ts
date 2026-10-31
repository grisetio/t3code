import type { ReactNode } from "react";

export interface SheetProps {
  /** Without one, the sheet has no header: it closes by dragging down or Back. */
  readonly title?: string;
  readonly children: ReactNode;
  readonly onClose: () => void;
}
