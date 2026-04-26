"""Unified ingest pipeline creation and execution."""

from __future__ import annotations

from typing import Any

from haystack import Pipeline
from haystack.components.joiners import DocumentJoiner
from haystack.document_stores.in_memory import InMemoryDocumentStore
from loguru import logger

from rag.index.store import PersistentFaissDocumentStore
from rag.ingest.cleaner import create_document_cleaner
from rag.ingest.converter import create_pdf_converter, create_txt_converter
from rag.ingest.embedder import create_document_embedder
from rag.ingest.metadata import (
  ChunkMetadataEnricher,
  DocumentMetadataEnricher,
  build_file_metadata_map,
  collect_dataset_selection,
)
from rag.ingest.router import create_file_router
from rag.ingest.splitter import create_document_splitter
from rag.ingest.writer import create_document_store, create_document_writer


def build_ingest_pipeline(
  config: dict[str, Any],
  metadata_map: dict[str, dict[str, Any]],
  document_store: InMemoryDocumentStore | PersistentFaissDocumentStore | None = None,
) -> tuple[Pipeline, InMemoryDocumentStore | PersistentFaissDocumentStore]:
  """Build the Haystack ingest pipeline for the selected dataset."""
  if document_store is None:
    document_store = create_document_store(config)

  router = create_file_router()
  pdf_converter = create_pdf_converter()
  txt_converter = create_txt_converter()
  joiner = DocumentJoiner()
  cleaner = create_document_cleaner()
  metadata_enricher = DocumentMetadataEnricher(metadata_map)
  splitter = create_document_splitter(config)
  chunk_enricher = ChunkMetadataEnricher()
  embedder = create_document_embedder(config)
  writer = create_document_writer(document_store)

  pipeline = Pipeline()
  pipeline.add_component("router", router)
  pipeline.add_component("pdf_converter", pdf_converter)
  pipeline.add_component("txt_converter", txt_converter)
  pipeline.add_component("joiner", joiner)
  pipeline.add_component("cleaner", cleaner)
  pipeline.add_component("metadata_enricher", metadata_enricher)
  pipeline.add_component("splitter", splitter)
  pipeline.add_component("chunk_enricher", chunk_enricher)
  pipeline.add_component("embedder", embedder)
  pipeline.add_component("writer", writer)

  pipeline.connect("router.application/pdf", "pdf_converter.sources")
  pipeline.connect("router.text/plain", "txt_converter.sources")
  pipeline.connect("router.text/markdown", "txt_converter.sources")
  pipeline.connect("pdf_converter.documents", "joiner.documents")
  pipeline.connect("txt_converter.documents", "joiner.documents")
  pipeline.connect("joiner.documents", "cleaner.documents")
  pipeline.connect("cleaner.documents", "metadata_enricher.documents")
  pipeline.connect("metadata_enricher.documents", "splitter.documents")
  pipeline.connect("splitter.documents", "chunk_enricher.documents")
  pipeline.connect("chunk_enricher.documents", "embedder.documents")
  pipeline.connect("embedder.documents", "writer.documents")

  logger.info("Ingest pipeline built")
  return pipeline, document_store


def run_ingest_files(
  file_paths: list[str],
  config: dict[str, Any],
  *,
  metadata_map: dict[str, dict[str, Any]],
  document_store: InMemoryDocumentStore | PersistentFaissDocumentStore | None = None,
) -> tuple[InMemoryDocumentStore | PersistentFaissDocumentStore, int]:
  """Run the ingest pipeline for an explicit subset of selected files."""
  if not file_paths:
    if document_store is None:
      raise ValueError("A document store is required when no files are selected.")
    return document_store, 0

  pipeline, document_store = build_ingest_pipeline(
    config,
    metadata_map,
    document_store,
  )
  pipeline.warm_up()

  logger.info("Running ingest pipeline for {} selected files...", len(file_paths))
  result = pipeline.run({"router": {"sources": file_paths}})
  docs_written = result.get("writer", {}).get("documents_written", 0)
  logger.info("Ingest complete: {} chunks written", docs_written)
  return document_store, docs_written


def run_ingest(
  doc_path: str,
  config: dict[str, Any],
  environment: str | None = None,
  scenario: str | None = None,
  document_store: InMemoryDocumentStore | PersistentFaissDocumentStore | None = None,
) -> tuple[InMemoryDocumentStore | PersistentFaissDocumentStore, int]:
  """Collect files for one dataset scope and write them into the store."""
  selection = collect_dataset_selection(
    doc_path,
    environment=environment,
    scenario=scenario,
  )
  if not selection.file_paths:
    raise ValueError(
      f"No supported document files (.pdf, .txt, .md) were found: {selection.dataset_root}"
    )

  logger.info(
    "Selected {} files from {} (dataset_scope={}, mode={})",
    len(selection.file_paths),
    selection.dataset_root,
    selection.dataset_scope,
    selection.dataset_selection_mode,
  )
  for file_path in selection.file_paths:
    logger.debug("  - {}", file_path)

  metadata_map = build_file_metadata_map(
    selection.file_paths,
    selection.dataset_root,
    environment=selection.environment_scope,
    scenario=selection.scenario_scope,
    dataset_selection_mode=selection.dataset_selection_mode,
  )
  return run_ingest_files(
    selection.file_paths,
    config,
    metadata_map=metadata_map,
    document_store=document_store,
  )
