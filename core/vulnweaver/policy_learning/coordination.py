"""Dependency-aware task assignment for the hierarchical coordinator."""

from __future__ import annotations

from vulnweaver.common.schema import AgentOperation, Assignment, CaseSpec, Trajectory


class CoordinationError(ValueError):
    """Raised when a case cannot be converted into a legal assignment plan."""


class HierarchicalCoordinator:
    """Build a deterministic legal plan without executing or generating candidates.

    Tasks are released only after all prerequisites complete. Within each ready set,
    their order follows the immutable case specification. The first allow-listed
    capability for the task's required role becomes the planned operation; policy
    implementations may replace that selection while preserving the same constraints.
    """

    def plan(self, case: CaseSpec) -> Trajectory:
        trajectory = Trajectory(case_id=case.case_id)
        pending = {task.task_id: task for task in case.tasks}
        completed: set[str] = set()
        sequence = 0

        while pending:
            ready = [
                task
                for task in case.tasks
                if task.task_id in pending and set(task.prerequisites) <= completed
            ]
            if not ready:
                blocked = ", ".join(sorted(pending))
                raise CoordinationError(f"task dependency graph is cyclic or blocked: {blocked}")

            for task in ready:
                capabilities = case.allowed_operations.get(task.required_role, ())
                if not capabilities:
                    raise CoordinationError(
                        f"role {task.required_role.value!r} has no allow-listed capability"
                    )
                assignment = Assignment(
                    assignment_id=f"assignment-{sequence}",
                    task_id=task.task_id,
                    agent_role=task.required_role,
                    sequence=sequence,
                )
                trajectory.assignments.append(assignment)
                trajectory.operations.append(
                    AgentOperation(
                        operation_id=f"operation-{sequence}",
                        assignment_id=assignment.assignment_id,
                        role=task.required_role,
                        capability=capabilities[0],
                    )
                )
                completed.add(task.task_id)
                pending.pop(task.task_id)
                sequence += 1

        return trajectory
