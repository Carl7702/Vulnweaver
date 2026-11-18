"""The `vw` command-line entry point."""

from __future__ import annotations

import json
import platform
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer

from vulnweaver import __version__
from vulnweaver.common.config import load_config
from vulnweaver.common.protocols import ExecutionBackend
from vulnweaver.common.schema import OperationStatus
from vulnweaver.experiments.adapters.ase import scan_ase, write_import
from vulnweaver.experiments.adapters.cve import build_cve_catalog, write_cve_catalog
from vulnweaver.experiments.adapters.defihacklabs import (
    PINNED_COMMIT,
    scan_defihacklabs,
    write_defihacklabs_import,
)
from vulnweaver.experiments.adapters.forge import scan_forge, write_forge_import
from vulnweaver.experiments.datasets import (
    PAPER_TARGET_COUNTS,
    EvaluationDataset,
    EvaluationRecord,
    EvaluationRejectionReason,
    build_ase_evaluation_records,
    build_evaluation_manifest,
    build_inc_evaluation_records,
    empty_evaluation_dataset,
    evaluation_input_hashes,
    load_cve_catalog,
    write_evaluation_import,
)
from vulnweaver.experiments.reporting import build_report, write_report
from vulnweaver.experiments.runner import (
    DEFAULT_METHODS,
    ExperimentBudget,
    ExperimentMethod,
    discover_experiment_cases,
    load_experiment_run,
    run_experiment,
    write_experiment_summary,
)
from vulnweaver.policy_learning.models import FakeModelBackend, ModelMessage
from vulnweaver.policy_learning.training import (
    HierarchicalPPOTrainer,
    TrainingConfig,
    write_training_result,
)
from vulnweaver.task_construction.cases import CaseLoadError, case_hash, load_case
from vulnweaver.validation.execution import DEFAULT_FOUNDRY_IMAGE, DockerFoundryBackend
from vulnweaver.validation.obligations import TemplateObligationEvaluator
from vulnweaver.validation.replay import ReplayExecutionBackend, load_replay_bundle
from vulnweaver.validation.verifier import IndependentVerifier

app = typer.Typer(
    name="vw",
    help="Reproducible construction and causal validation of vulnerability PoCs.",
    no_args_is_help=True,
)
dataset_app = typer.Typer(help="Import, normalize, and admit dataset cases.", no_args_is_help=True)
case_app = typer.Typer(help="Inspect normalized cases.", no_args_is_help=True)
app.add_typer(dataset_app, name="dataset")
app.add_typer(case_app, name="case")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = None,
) -> None:
    """VulnWeaver research CLI."""


@app.command()
def doctor(
    config: Annotated[Path, typer.Option(exists=True, dir_okay=False)] = Path(
        "training/config/default.toml"
    ),
    check_container: Annotated[
        bool, typer.Option(help="Also run the pinned Foundry image (may pull it).")
    ] = False,
) -> None:
    """Check the local core toolchain without reading secrets."""

    loaded = load_config(config)
    checks = {
        "python": platform.python_version(),
        "python_supported": sys.version_info[:2] == (3, 11),
        "docker_cli": shutil.which("docker") is not None,
        "host_forge": shutil.which("forge") is not None,
        "config": str(config),
        "config_loaded": True,
    }
    container_ok = True
    if check_container:
        execution = loaded.get("execution", {})
        backend = DockerFoundryBackend(
            image=str(execution.get("image", DEFAULT_FOUNDRY_IMAGE)),
            timeout_seconds=int(execution.get("timeout_seconds", 120)),
        )
        result = backend.smoke(Path.cwd())
        checks["foundry_container"] = result.status.value
        checks["foundry_error_kind"] = result.error_kind.value
        checks["foundry_output"] = result.message
        container_ok = result.status is OperationStatus.SUCCEEDED
    typer.echo(json.dumps(checks, indent=2, sort_keys=True))
    if not checks["python_supported"] or not container_ok:
        raise typer.Exit(code=1)


@dataset_app.command("import-ase")
def import_ase(
    source: Annotated[Path, typer.Argument(exists=True)],
    output: Annotated[Path, typer.Option()] = Path("datasets/imported/ase"),
    require_source: Annotated[
        bool,
        typer.Option(help="Reject candidates whose declared contract path is unavailable."),
    ] = False,
    source_root: Annotated[
        Path | None,
        typer.Option(exists=True, file_okay=False, help="Optional contract source checkout."),
    ] = None,
) -> None:
    """Import ASE26 project_info/findings through the read-only adapter."""

    candidates, manifest = scan_ase(
        source,
        require_source=require_source,
        source_root=source_root,
    )
    write_import(output, candidates, manifest)
    typer.echo(manifest.model_dump_json(indent=2))


@dataset_app.command("import-defihacklabs")
def import_defihacklabs(
    source: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    output: Annotated[Path, typer.Option()] = Path("datasets/imported/defihacklabs"),
    cutoff_month: Annotated[
        str, typer.Option(help="Inclusive YYYY-MM incident cutoff for the training pool.")
    ] = "2022-12",
    validation_count: Annotated[
        int, typer.Option(min=0, help="Requested validation size after leakage grouping.")
    ] = 24,
) -> None:
    """Import metadata from an exact, separately cloned DeFiHackLabs checkout."""

    try:
        candidates, manifest = scan_defihacklabs(
            source,
            cutoff_month=cutoff_month,
            validation_count=validation_count,
            pinned_commit=PINNED_COMMIT,
        )
        write_defihacklabs_import(output, candidates, manifest)
    except (OSError, RuntimeError, ValueError) as error:
        typer.echo(f"DeFiHackLabs import failed: {error}", err=True)
        raise typer.Exit(code=1) from error
    typer.echo(manifest.model_dump_json(indent=2))


@dataset_app.command("import-forge")
def import_forge(
    source: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    output: Annotated[Path, typer.Option()] = Path("datasets/imported/forge"),
) -> None:
    """Import one candidate per finding from a pinned FORGE checkout."""

    candidates, manifest = scan_forge(source)
    write_forge_import(output, candidates, manifest)
    typer.echo(manifest.model_dump_json(indent=2))


@dataset_app.command("import-cve")
def import_cve(
    records_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    paper_table: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    repositories_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    snapshots_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    output: Annotated[Path, typer.Option()] = Path("datasets/imported/cve/catalog.json"),
) -> None:
    """Build the declared 18-case catalog from official CVEProject records."""

    catalog = build_cve_catalog(records_dir, paper_table, repositories_dir, snapshots_dir)
    write_cve_catalog(output, catalog)
    summary = {key: value for key, value in catalog.items() if key != "records"}
    typer.echo(json.dumps(summary, indent=2))


@dataset_app.command("admit")
def admit(
    case_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    verify_inputs: Annotated[bool, typer.Option()] = True,
) -> None:
    """Validate a case schema, graph, optional input hashes, and print its stable hash."""

    try:
        case = load_case(case_path, verify_inputs=verify_inputs)
    except CaseLoadError as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(code=1) from error
    typer.echo(
        json.dumps({"case_id": case.case_id, "status": "SCHEMA_VALID", "hash": case_hash(case)})
    )


@dataset_app.command("build-evaluation")
def build_evaluation(
    output: Annotated[Path, typer.Option()] = Path("datasets/imported/evaluation"),
    ase_source: Annotated[
        Path | None,
        typer.Option(help="ASE26 directory or ZIP; omitted inputs are recorded as unavailable."),
    ] = None,
    defihacklabs_source: Annotated[
        Path | None,
        typer.Option(help="Pinned DeFiHackLabs checkout for D_inc."),
    ] = None,
    cve_catalog: Annotated[
        Path | None,
        typer.Option(help="Version-pinned CVE catalog JSON."),
    ] = None,
) -> None:
    """Build D_mix/D_log/D_inc/D_cve records and their discrepancy data card."""

    records: list[EvaluationRecord] = []
    input_paths: dict[str, Path] = {}
    if ase_source is None:
        for dataset in (EvaluationDataset.D_MIX, EvaluationDataset.D_LOG):
            records.extend(
                empty_evaluation_dataset(dataset, EvaluationRejectionReason.CATALOG_NOT_PROVIDED)
            )
    else:
        from vulnweaver.experiments.adapters.ase import scan_ase

        ase_candidates, _ = scan_ase(ase_source)
        records.extend(build_ase_evaluation_records(ase_candidates))
        input_paths["ase_source"] = ase_source

    if defihacklabs_source is None:
        records.extend(
            empty_evaluation_dataset(
                EvaluationDataset.D_INC, EvaluationRejectionReason.CATALOG_NOT_PROVIDED
            )
        )
    else:
        train_candidates, _ = scan_defihacklabs(
            defihacklabs_source,
            cutoff_month="2022-12",
            validation_count=24,
            pinned_commit=PINNED_COMMIT,
        )
        all_candidates, _ = scan_defihacklabs(
            defihacklabs_source,
            cutoff_month="2099-12",
            validation_count=0,
            pinned_commit=PINNED_COMMIT,
        )
        records.extend(
            build_inc_evaluation_records(
                all_candidates,
                train_candidates,
                cutoff_month="2022-12",
                target_count=PAPER_TARGET_COUNTS[EvaluationDataset.D_INC],
            )
        )
        input_paths["defihacklabs_source"] = defihacklabs_source

    if cve_catalog is None:
        records.extend(
            empty_evaluation_dataset(
                EvaluationDataset.D_CVE, EvaluationRejectionReason.CATALOG_NOT_PROVIDED
            )
        )
    else:
        records.extend(load_cve_catalog(cve_catalog))
        input_paths["cve_catalog"] = cve_catalog

    manifest = build_evaluation_manifest(
        records,
        source_inputs=evaluation_input_hashes(input_paths),
        target_counts={key.value: value for key, value in PAPER_TARGET_COUNTS.items()},
    )
    write_evaluation_import(output, records, manifest)
    typer.echo(manifest.model_dump_json(indent=2))


@case_app.command("inspect")
def inspect_case(
    case_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    """Print a normalized case and its deterministic hash without executing code."""

    try:
        case = load_case(case_path)
    except CaseLoadError as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(code=1) from error
    typer.echo(
        json.dumps(
            {
                "hash": case_hash(case),
                "case": case.model_dump(mode="json", by_alias=True),
            },
            indent=2,
            sort_keys=True,
        )
    )


@app.command()
def verify(
    case_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    candidate: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    replay: Annotated[
        Path | None,
        typer.Option(exists=True, dir_okay=False, help="Offline execution evidence bundle."),
    ] = None,
    config: Annotated[
        Path,
        typer.Option(exists=True, dir_okay=False, help="Runtime configuration for live replay."),
    ] = Path("training/config/default.toml"),
    repository_root: Annotated[
        Path,
        typer.Option(
            exists=True,
            file_okay=False,
            help="Root used to resolve case environment repositories.",
        ),
    ] = Path("."),
) -> None:
    """Independently verify one candidate live or from captured evidence."""

    try:
        case = load_case(case_path, verify_inputs=True)
    except (CaseLoadError, OSError, ValueError) as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(code=1) from error

    backend_factory: Callable[[], ExecutionBackend]
    if replay is not None:
        try:
            bundle = load_replay_bundle(replay)
        except (OSError, ValueError) as error:
            typer.echo(str(error), err=True)
            raise typer.Exit(code=1) from error
        actual_case_hash = case_hash(case)
        if bundle.case_sha256 != actual_case_hash:
            typer.echo(
                f"replay/case hash mismatch: {bundle.case_sha256} != {actual_case_hash}",
                err=True,
            )
            raise typer.Exit(code=1)
        records = {record.environment_id: record for record in bundle.records}

        def replay_backend_factory() -> ReplayExecutionBackend:
            return ReplayExecutionBackend(records)

        backend_factory = replay_backend_factory
    else:
        loaded = load_config(config)
        execution = loaded.get("execution", {})
        image = str(execution.get("image", DEFAULT_FOUNDRY_IMAGE))
        timeout_seconds = int(execution.get("timeout_seconds", 120))
        resolved_root = repository_root.resolve()

        def backend_factory() -> DockerFoundryBackend:
            return DockerFoundryBackend(
                image=image,
                timeout_seconds=timeout_seconds,
                repository_root=resolved_root,
            )

    verifier = IndependentVerifier(
        backend_factory,
        TemplateObligationEvaluator(),
    )
    try:
        report = verifier.verify(candidate, case)
    except (OSError, RuntimeError, ValueError) as error:
        typer.echo(f"verification failed: {error}", err=True)
        raise typer.Exit(code=1) from error
    typer.echo(report.model_dump_json(indent=2))


@app.command()
def train(
    iterations: Annotated[int, typer.Option(min=1, help="PPO iterations to run.")] = 10,
    episodes_per_iteration: Annotated[
        int, typer.Option(min=1, help="On-policy episodes collected per iteration.")
    ] = 32,
    checkpoint: Annotated[
        Path, typer.Option(help="Checkpoint path to write after training.")
    ] = Path("checkpoints/hierarchical-ppo.pt"),
    result_path: Annotated[Path, typer.Option(help="JSON training result path.")] = Path(
        "results/training/result.json"
    ),
    seed: Annotated[int, typer.Option(help="Deterministic training seed.")] = 42,
) -> None:
    """Train the masked hierarchical PPO smoke policy."""

    config = TrainingConfig(
        episodes_per_iteration=episodes_per_iteration,
        max_iterations=iterations,
        seed=seed,
    )
    result = HierarchicalPPOTrainer(config).train(
        iterations=iterations,
        checkpoint=checkpoint,
    )
    write_training_result(result_path, result)
    typer.echo(json.dumps(result.__dict__, indent=2, sort_keys=True))


@app.command()
def evaluate(
    cases_root: Annotated[
        Path,
        typer.Option(
            exists=True,
            file_okay=False,
            help="Directory containing complete case.json/replay.json pairs.",
        ),
    ] = Path("datasets"),
    output: Annotated[
        Path, typer.Option(help="Directory for the run manifest, metrics, and evidence.")
    ] = Path("results/evaluation"),
    methods: Annotated[
        str,
        typer.Option(
            help="Comma-separated methods; omit to run all baseline and reward profiles."
        ),
    ] = ",".join(method.value for method in DEFAULT_METHODS),
    pocforge_source: Annotated[
        Path | None,
        typer.Option(
            exists=True,
            file_okay=False,
            help="Optional PoCForge checkout used only for baseline provenance.",
        ),
    ] = None,
    seed: Annotated[int, typer.Option(help="Deterministic experiment seed.")] = 42,
) -> None:
    """Run selected offline protocol profiles under one shared budget and verifier."""

    try:
        selected = tuple(
            ExperimentMethod(item.strip())
            for item in methods.split(",")
            if item.strip()
        )
        cases = discover_experiment_cases(cases_root)
        run = run_experiment(
            cases,
            output,
            methods=selected,
            budget=ExperimentBudget.paper_default(),
            seed=seed,
            pocforge_source=pocforge_source,
        )
        write_experiment_summary(output / "summary.md", run)
    except (OSError, ValueError, RuntimeError) as error:
        typer.echo(f"evaluation failed: {error}", err=True)
        raise typer.Exit(code=1) from error
    typer.echo(run.model_dump_json(indent=2))


@app.command()
def report(
    run_path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            dir_okay=False,
            help="experiment.json produced by vw evaluate.",
        ),
    ] = Path("results/evaluation/experiment.json"),
    output: Annotated[
        Path, typer.Option(help="Directory for report.json, report.md, and paper-table.csv.")
    ] = Path("results/report"),
    evaluation_manifest: Annotated[
        Path | None,
        typer.Option(
            exists=True,
            dir_okay=False,
            help="Optional evaluation import-manifest.json for discrepancy reporting.",
        ),
    ] = None,
    bootstrap_samples: Annotated[
        int,
        typer.Option(min=1, help="Project-clustered bootstrap and paired-permutation samples."),
    ] = 10_000,
    seed: Annotated[int, typer.Option(help="Deterministic resampling seed.")] = 42,
) -> None:
    """Aggregate metrics, uncertainty, failures, and dataset discrepancies."""

    try:
        run = load_experiment_run(run_path)
        result = build_report(
            run,
            bootstrap_samples=bootstrap_samples,
            seed=seed,
            evaluation_manifest=evaluation_manifest,
        )
        write_report(output, result)
    except (OSError, ValueError, RuntimeError) as error:
        typer.echo(f"report failed: {error}", err=True)
        raise typer.Exit(code=1) from error
    typer.echo(result.model_dump_json(indent=2))


@app.command("smoke-fake-model")
def smoke_fake_model() -> None:
    """Exercise the offline model path without network or credentials."""

    backend = FakeModelBackend(["offline-ok"])
    response = backend.complete([ModelMessage(role="user", content="health check")])
    typer.echo(response.content)


if __name__ == "__main__":
    app()
