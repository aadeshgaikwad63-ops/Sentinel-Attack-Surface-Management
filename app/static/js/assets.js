// SentinelASM — Asset Inventory table interactions
// Operates entirely on rows already rendered by the server (no fabricated
// data): search, type/risk filters, column sorting, client-side pagination,
// row selection with a bulk-action bar, and CSV/JSON export.
(() => {
  const table = document.getElementById("assetsTable");
  if (!table) return;

  const tbody = table.querySelector("tbody");
  const allRows = Array.from(tbody.querySelectorAll("tr.asset-row"));
  if (allRows.length === 0) return; // nothing to wire up for the empty state

  // Technology chip icons — derived once from the real detected tech string.
  allRows.forEach((row) => {
    const iconEl = row.querySelector(".tech-icon");
    if (iconEl) iconEl.className = `tech-icon me-1 ${window.Sentinel.techIcon(row.dataset.tech)}`;
  });

  const PAGE_SIZE = 8;
  let currentPage = 1;
  let sortKey = null;
  let sortDir = 1;

  const searchInput = document.getElementById("assetSearch");
  const typeFilter = document.getElementById("assetTypeFilter");
  const riskFilter = document.getElementById("assetRiskFilter");
  const selectAll = document.getElementById("selectAllAssets");
  const bulkBar = document.getElementById("assetBulkBar");
  const bulkCount = document.getElementById("assetBulkCount");
  const paginationEl = document.getElementById("assetsPagination");
  const summaryEl = document.getElementById("assetsSummary");

  function getFiltered() {
    const q = (searchInput?.value || "").trim().toLowerCase();
    const type = (typeFilter?.value || "all").toLowerCase();
    const risk = (riskFilter?.value || "all").toLowerCase();

    return allRows.filter((row) => {
      const name = row.dataset.name || "";
      const tech = row.dataset.tech || "";
      const rowType = row.dataset.type || "";
      const rowRisk = row.dataset.risk || "";
      if (q && !name.includes(q) && !tech.includes(q)) return false;
      if (type !== "all" && rowType !== type) return false;
      if (risk !== "all" && rowRisk !== risk) return false;
      return true;
    });
  }

  function sortRows(rows) {
    if (!sortKey) return rows;
    return rows.slice().sort((a, b) => {
      const av = (a.dataset[sortKey] || "").toString();
      const bv = (b.dataset[sortKey] || "").toString();
      return av.localeCompare(bv, undefined, { numeric: true }) * sortDir;
    });
  }

  function render() {
    allRows.forEach((r) => (r.style.display = "none"));

    const filtered = sortRows(getFiltered());
    const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
    currentPage = Math.min(currentPage, totalPages);
    const start = (currentPage - 1) * PAGE_SIZE;
    const pageRows = filtered.slice(start, start + PAGE_SIZE);

    pageRows.forEach((r) => (r.style.display = ""));

    if (summaryEl) {
      summaryEl.textContent = filtered.length
        ? `Showing ${start + 1}-${start + pageRows.length} of ${filtered.length} assets`
        : "No assets match your filters";
    }

    renderPagination(totalPages, filtered.length);
    if (selectAll) selectAll.checked = false;
    updateBulkBar();
  }

  function renderPagination(totalPages, total) {
    if (!paginationEl) return;
    paginationEl.innerHTML = "";
    if (total <= PAGE_SIZE) return; // only one page — nothing to page through

    const makeBtn = (label, page, disabled, active) => {
      const li = document.createElement("li");
      li.className = `page-item${disabled ? " disabled" : ""}${active ? " active" : ""}`;
      const a = document.createElement("a");
      a.className = "page-link";
      a.href = "#";
      a.textContent = label;
      a.style.background = active ? "var(--green)" : "var(--card)";
      a.style.borderColor = active ? "var(--green)" : "var(--border-strong)";
      a.style.color = active ? "#052A20" : disabled ? "var(--text-muted)" : "var(--text-primary)";
      if (!disabled) {
        a.addEventListener("click", (e) => {
          e.preventDefault();
          currentPage = page;
          render();
        });
      }
      li.appendChild(a);
      return li;
    };

    paginationEl.appendChild(makeBtn("Prev", currentPage - 1, currentPage === 1, false));
    for (let p = 1; p <= totalPages; p++) {
      paginationEl.appendChild(makeBtn(String(p), p, false, p === currentPage));
    }
    paginationEl.appendChild(makeBtn("Next", currentPage + 1, currentPage === totalPages, false));
  }

  function updateBulkBar() {
    const checked = tbody.querySelectorAll(".row-check:checked");
    if (!bulkBar) return;
    if (checked.length > 0) {
      bulkBar.style.display = "flex";
      if (bulkCount) bulkCount.textContent = `${checked.length} selected`;
    } else {
      bulkBar.style.display = "none";
    }
  }

  function visibleRows() {
    return allRows.filter((r) => r.style.display !== "none");
  }

  function rowToRecord(row) {
    return {
      Asset: row.dataset.name,
      Type: row.dataset.type,
      IP: row.dataset.ip,
      Technology: row.dataset.tech,
      "Open Ports": row.dataset.ports,
      Risk: row.dataset.risk,
      "Last Scanned": row.dataset.scanned,
      SSL: row.dataset.ssl,
    };
  }

  function exportRows(rows, format) {
    const records = rows.map(rowToRecord);
    if (records.length === 0) return;
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    if (format === "json") {
      window.Sentinel.download(`sentinelasm-assets-${stamp}.json`, JSON.stringify(records, null, 2), "application/json");
    } else {
      const headers = Object.keys(records[0]);
      window.Sentinel.download(`sentinelasm-assets-${stamp}.csv`, window.Sentinel.rowsToCSV(records, headers), "text/csv");
    }
  }

  // Filters
  searchInput?.addEventListener("input", () => {
    currentPage = 1;
    render();
  });
  typeFilter?.addEventListener("change", () => {
    currentPage = 1;
    render();
  });
  riskFilter?.addEventListener("change", () => {
    currentPage = 1;
    render();
  });

  // Sorting
  table.querySelectorAll("th[data-sort-key]").forEach((th) => {
    th.style.cursor = "pointer";
    th.addEventListener("click", () => {
      const key = th.dataset.sortKey;
      sortDir = sortKey === key ? sortDir * -1 : 1;
      sortKey = key;
      table.querySelectorAll("th[data-sort-key] i.sort-icon").forEach((i) => (i.className = "sort-icon fa-solid fa-sort ms-1 text-muted-2"));
      const icon = th.querySelector("i.sort-icon");
      if (icon) icon.className = `sort-icon fa-solid ${sortDir === 1 ? "fa-sort-up" : "fa-sort-down"} ms-1`;
      render();
    });
  });

  // Row selection
  selectAll?.addEventListener("change", () => {
    visibleRows().forEach((r) => {
      const cb = r.querySelector(".row-check");
      if (cb) cb.checked = selectAll.checked;
    });
    updateBulkBar();
  });
  tbody.addEventListener("change", (e) => {
    if (e.target.classList.contains("row-check")) updateBulkBar();
  });

  // Bulk + toolbar export
  document.getElementById("assetBulkExportCsv")?.addEventListener("click", () => {
    exportRows(Array.from(tbody.querySelectorAll(".row-check:checked")).map((cb) => cb.closest("tr")), "csv");
  });
  document.getElementById("assetBulkExportJson")?.addEventListener("click", () => {
    exportRows(Array.from(tbody.querySelectorAll(".row-check:checked")).map((cb) => cb.closest("tr")), "json");
  });
  document.getElementById("assetBulkClear")?.addEventListener("click", () => {
    tbody.querySelectorAll(".row-check:checked").forEach((cb) => (cb.checked = false));
    updateBulkBar();
  });
  document.getElementById("assetExportAllCsv")?.addEventListener("click", () => exportRows(allRows, "csv"));
  document.getElementById("assetExportAllJson")?.addEventListener("click", () => exportRows(allRows, "json"));

  document.getElementById("assetsRefresh")?.addEventListener("click", () => window.location.reload());

  render();
})();
