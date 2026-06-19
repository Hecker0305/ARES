import { cn } from "@/lib/utils";

interface PhaseProgressProps {
  phases: { id: number; name: string }[];
  selectedPhases?: number[];
  currentPhase?: number;
  completedPhases?: number[];
  className?: string;
}

export function PhaseProgress({
  phases,
  selectedPhases,
  currentPhase,
  completedPhases = [],
  className,
}: PhaseProgressProps) {
  return (
    <div className={cn("flex gap-0.5", className)}>
      {phases.map((phase) => {
        const isSelected = !selectedPhases || selectedPhases.includes(phase.id);
        const isCompleted = completedPhases.includes(phase.id);
        const isCurrent = currentPhase === phase.id;

        return (
          <div
            key={phase.id}
            className={cn(
              "h-1.5 flex-1 rounded-full transition-colors",
              !isSelected && "bg-muted/30",
              isCompleted && "bg-success",
              isCurrent && "bg-warning pulse-dot",
              isSelected && !isCompleted && !isCurrent && "bg-muted",
            )}
            title={`Phase ${phase.id}: ${phase.name}`}
          />
        );
      })}
    </div>
  );
}
