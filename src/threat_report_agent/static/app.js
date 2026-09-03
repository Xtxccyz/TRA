"use strict";

const moduleTitles = {
  executive_summary: "执行摘要",
  input_manifest: "输入清单",
  artifact_inventory: "样本与组件",
  static_triage: "静态分诊",
  decryption: "解密与解码",
  loader: "加载器",
  c2_network: "C2 与网络",
  anti_analysis: "反分析",
  behavior_attack: "行为与 ATT&CK",
  attribution: "聚合与归因",
  evidence_ledger: "证据账本",
  limitations: "限制与审计",
};

const state = {
  taskId: null,
  revisionId: null,
  gatePromise: null,
  gateResolver: null,
  gateId: null,
  modelConfigRevision: 0,
};

function byId(id) {
  return document.getElementById(id);
}

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined && text !== null) {
    element.textContent = String(text);
  }
  if (className) {
    element.className = className;
  }
  return element;
}

async function fetchJSON(url, options) {
  const response = await fetch(url, options);
  let payload;
  try {
    payload = await response.json();
  } catch {
    payload = { detail: response.statusText };
  }
  if (!response.ok) {
    const error = new Error(typeof payload.detail === "string" ? payload.detail : JSON.stringify(payload));
    error.status = response.status;
    throw error;
  }
  return payload;
}

function selectedModules() {
  return Array.from(document.querySelectorAll("[data-report-module]:checked")).map(
    (input) => input.value,
  );
}

async function initialize() {
  const health = await fetchJSON("/healthz");
  byId("systemState").textContent = health.status === "ok" ? "系统就绪" : "系统异常";
  document.querySelector(".state-dot").style.background =
    health.status === "ok" ? "#21a179" : "#c5473a";
  const capabilities = health.capabilities || {};
  const modelLabels = {
    deterministic_static_agent: "确定性静态回退（未配置模型）",
    model_agent_unconfigured_fallback: "模型 Agent 开关已开，但凭据未配置",
    model_agent_with_deterministic_fallback: "模型 Agent + 确定性回退",
  };
  byId("modelStatus").textContent = modelLabels[capabilities.agent_mode]
    || capabilities.agent_mode
    || "未知";
  await loadModelConfig();
  const meta = await fetchJSON("/api/v1/meta");
  const selector = byId("moduleSelector");
  meta.report_modules.forEach((moduleId) => {
    const label = node("label");
    const checkbox = node("input");
    checkbox.type = "checkbox";
    checkbox.value = moduleId;
    checkbox.checked = true;
    checkbox.dataset.reportModule = "true";
    label.append(checkbox, node("span", moduleTitles[moduleId] || moduleId));
    selector.append(label);
  });
}

function setModelRoute(prefix, route) {
  byId(prefix + "RouteEnabled").checked = route.enabled !== false;
  byId(prefix + "Provider").value = route.provider || "";
  byId(prefix + "BaseUrl").value = route.base_url || "";
  byId(prefix + "Model").value = route.model || "";
  byId(prefix + "ApiStyle").value = route.api_style === "anthropic" ? "anthropic" : "openai";
  byId(prefix + "Stream").checked = route.stream !== false;
  byId(prefix + "JsonMode").checked = route.supports_json_mode !== false;
  byId(prefix + "DisableReasoning").checked = route.disable_reasoning !== false;
  byId(prefix + "Temperature").value = route.temperature ?? 0;
  byId(prefix + "TopP").value = route.top_p ?? 1;
}

async function loadModelConfig() {
  try {
    const config = await fetchJSON("/api/v1/model-config");
    state.modelConfigRevision = config.revision || 0;
    byId("modelEnabled").checked = Boolean(config.enabled);
    byId("modelContextBytes").value = config.context_max_bytes || 2000000;
    byId("modelTimeout").value = config.timeout_s || 180;
    byId("modelMaxTokens").value = config.max_tokens || 2048;
    setModelRoute("primary", config.primary || {});
    setModelRoute("fallback", config.fallback || {});
    const source = config.source === "database" ? "服务端已保存配置" : "使用环境配置（尚未保存）";
    byId("modelConfigState").textContent = source
      + "；主模型密钥：" + (config.primary?.api_key_configured ? "已配置" : "未配置")
      + "，备用模型密钥：" + (config.fallback?.api_key_configured ? "已配置" : "未配置");
  } catch (error) {
    byId("modelConfigState").textContent = "无权查看或无法读取模型配置。";
  }
}

byId("modelConfigForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const saveButton = byId("saveModelConfigButton");
  saveButton.disabled = true;
  byId("modelConfigState").textContent = "正在加密保存配置……";
  const routePayload = (prefix) => {
    const apiKey = byId(prefix + "ApiKey").value;
    const route = {
      provider: byId(prefix + "Provider").value.trim(),
      base_url: byId(prefix + "BaseUrl").value.trim(),
      model: byId(prefix + "Model").value.trim(),
      api_style: byId(prefix + "ApiStyle").value,
      enabled: byId(prefix + "RouteEnabled").checked,
      stream: byId(prefix + "Stream").checked,
      supports_json_mode: byId(prefix + "JsonMode").checked,
      disable_reasoning: byId(prefix + "DisableReasoning").checked,
      temperature: Number(byId(prefix + "Temperature").value),
      top_p: Number(byId(prefix + "TopP").value),
      clear_api_key: byId("clear" + (prefix === "primary" ? "Primary" : "Fallback") + "ApiKey").checked,
    };
    if (apiKey) {
      route.api_key = apiKey;
    }
    return route;
  };
  try {
    const config = await fetchJSON("/api/v1/model-config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        expected_revision: state.modelConfigRevision,
        enabled: byId("modelEnabled").checked,
        context_max_bytes: Number(byId("modelContextBytes").value),
        timeout_s: Number(byId("modelTimeout").value),
        max_tokens: Number(byId("modelMaxTokens").value),
        primary: routePayload("primary"),
        fallback: routePayload("fallback"),
      }),
    });
    state.modelConfigRevision = config.revision || state.modelConfigRevision;
    byId("primaryApiKey").value = "";
    byId("fallbackApiKey").value = "";
    byId("clearPrimaryApiKey").checked = false;
    byId("clearFallbackApiKey").checked = false;
    byId("modelConfigState").textContent = "配置已保存并立即生效。密钥不会在页面显示。";
    byId("modelStatus").textContent = config.enabled
      ? "模型 Agent + 确定性回退"
      : "确定性静态回退（模型未启用）";
  } catch (error) {
    byId("primaryApiKey").value = "";
    byId("fallbackApiKey").value = "";
    byId("clearPrimaryApiKey").checked = false;
    byId("clearFallbackApiKey").checked = false;
    byId("modelConfigState").textContent = error.status === 409
      ? "配置版本已变化，请重新加载页面后再保存。"
      : (error.message || "配置保存失败。");
  } finally {
    saveButton.disabled = false;
  }
});

byId("sampleFile").addEventListener("change", (event) => {
  const files = Array.from(event.target.files || []);
  const file = files[0];
  byId("manifestSample").textContent = file ? file.name : "待选择";
});

byId("backgroundContext").addEventListener("input", (event) => {
  byId("manifestBackground").textContent = event.target.value.trim() ? "已提供 · 独立通道" : "独立通道";
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((panel) => {
      panel.hidden = panel.id !== tab.dataset.panel;
    });
    tab.classList.add("active");
  });
});

byId("analysisForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const files = Array.from(byId("sampleFile").files || []);
  if (!files.length) {
    return;
  }
  const submitButton = byId("submitButton");
  submitButton.disabled = true;
  byId("submitState").textContent = "分析中";
  byId("manifestRequest").textContent = "冻结中";
  try {
    const caseRecord = await fetchJSON("/api/v1/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: byId("caseTitle").value }),
    });
    const form = new FormData();
    files.forEach((file) => form.append("sample", file));
    form.append("background_context", byId("backgroundContext").value);
    form.append("selected_modules", JSON.stringify(selectedModules()));
    const result = await fetchJSON("/api/v1/cases/" + caseRecord.id + "/tasks", {
      method: "POST",
      headers: { "Idempotency-Key": crypto.randomUUID() },
      body: form,
    });
    state.taskId = result.task_id;
    byId("manifestRequest").textContent = "已冻结";
    const task = await waitForTask(result.task_id);
    byId("submitState").textContent =
      task.lifecycle === "WAITING_GATE" ? "等待输入审核" : "分析完成";
  } catch (error) {
    byId("submitState").textContent = error.message;
  } finally {
    submitButton.disabled = false;
  }
});

function populateTableBody(body, rows) {
  body.replaceChildren();
  rows.forEach((cells) => {
    const row = node("tr");
    cells.forEach((cell) => row.append(node("td", cell)));
    body.append(row);
  });
}

async function loadTask(taskId) {
  const task = await fetchJSON("/api/v1/tasks/" + taskId);
  byId("resultSection").hidden = false;
  byId("resultTitle").textContent = task.case_title;
  byId("lifecycleStatus").textContent = task.lifecycle;
  byId("outcomeStatus").textContent = task.outcome || "未计算";
  byId("analysisClassStatus").textContent = task.analysis_class || "未分类";
  byId("artifactCount").textContent = task.artifacts.length;
  byId("toolRunCount").textContent = task.tool_runs.length;
  byId("evidenceCount").textContent = task.evidence.length;
  byId("claimCount").textContent = task.claims.length;
  populateTableBody(
    byId("artifactRows"),
    task.artifacts.map((artifact) => [
      artifact.logical_path,
      artifact.detected_type,
      artifact.obligation,
      artifact.sha256,
    ]),
  );
  renderClaims(task.claims);
  renderLimitations(task.limitations);
  renderEvidence(task.evidence);
  await loadAnalysisTrace(taskId);
  if (task.latest_report_revision_id) {
    await loadReport(task.latest_report_revision_id);
  } else {
    byId("reportEditor").value = "";
    updateDownloads(null);
  }
  byId("resultSection").scrollIntoView({ behavior: "smooth", block: "start" });
  return task;
}

async function waitForTask(taskId) {
  const settled = new Set(["PAUSED", "SUCCEEDED", "FAILED", "CANCELLED"]);
  for (let attempt = 0; attempt < 900; attempt += 1) {
    const task = await loadTask(taskId);
    if (task.lifecycle === "WAITING_GATE") {
      await waitForInputGate(task);
      continue;
    }
    if (settled.has(task.lifecycle)) {
      return task;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error("任务状态查询超时");
}

function pendingInputGate(task) {
  return (task.gates || []).find(
    (gate) => gate.type === "INPUT_REVIEW" && gate.status === "PENDING",
  );
}

function gateArchiveLabel(gate) {
  const context = gate?.context || {};
  return context.archive || context.logical_path || context.entry || "上传的压缩包";
}

function closeGateModal() {
  byId("gateModal").hidden = true;
  byId("gatePassword").value = "";
  byId("gateState").textContent = "";
  byId("gateApproveButton").disabled = false;
  byId("gateRejectButton").disabled = false;
}

function resolveGate(result) {
  const resolver = state.gateResolver;
  state.gateResolver = null;
  state.gatePromise = null;
  state.gateId = null;
  if (resolver) {
    resolver(result);
  }
}

async function submitGateDecision(gate, decision) {
  const passwordInput = byId("gatePassword");
  const password = decision === "APPROVE" ? passwordInput.value : "";
  if (decision === "APPROVE" && !password) {
    byId("gateState").textContent = "请输入解压密码。";
    passwordInput.focus();
    return;
  }
  byId("gateApproveButton").disabled = true;
  byId("gateRejectButton").disabled = true;
  byId("gateState").textContent = decision === "APPROVE" ? "正在验证密码并继续分析……" : "正在取消任务……";
  try {
    const result = await fetchJSON("/api/v1/gates/" + gate.id + "/decision", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(decision === "APPROVE"
        ? { decision, archive_password: password }
        : { decision }),
    });
    closeGateModal();
    resolveGate(result);
  } catch (error) {
    // Do not echo server errors: a password must not appear in UI diagnostics.
    byId("gateState").textContent = error.status === 409
      ? "密码不正确或压缩包仍无法解压，请重试。"
      : "无法提交审核决定，请检查服务状态后重试。";
    byId("gatePassword").value = "";
    byId("gateApproveButton").disabled = false;
    byId("gateRejectButton").disabled = false;
    byId("gatePassword").focus();
  }
}

function waitForInputGate(task) {
  const gate = pendingInputGate(task);
  if (!gate) {
    throw new Error("任务需要输入审核，但没有找到待处理 Gate。");
  }
  if (state.gatePromise && state.gateId === gate.id) {
    return state.gatePromise;
  }
  state.gateId = gate.id;
  state.gatePromise = new Promise((resolve) => {
    state.gateResolver = resolve;
  });
  byId("gateReason").textContent = gate.reason || "该压缩包需要人工确认后才能安全解压。";
  byId("gateArchive").textContent = "对象：" + gateArchiveLabel(gate);
  byId("gatePassword").value = "";
  byId("gateState").textContent = "密码只用于本次安全解压，不会写入报告或日志。";
  byId("gateModal").hidden = false;
  byId("gatePassword").focus();
  return state.gatePromise;
}

byId("gateForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.gateId) {
    await submitGateDecision({ id: state.gateId }, "APPROVE");
  }
});

byId("gateRejectButton").addEventListener("click", async () => {
  if (state.gateId) {
    await submitGateDecision({ id: state.gateId }, "REJECT");
  }
});

function renderClaims(claims) {
  const container = byId("claimRows");
  container.replaceChildren();
  if (!claims.length) {
    container.append(node("p", "未形成静态推断 Claim。"));
    return;
  }
  claims.forEach((claim) => {
    const row = node("article", null, "claim-row");
    row.append(node("p", claim.statement));
    const mappings = claim.attack_mapping?.mappings || [];
    const mapping = claim.attack_mapping?.technique_id
      || mappings.map((item) => item.technique_id).filter(Boolean).join(", ")
      || "无 ATT&CK 映射";
    row.append(
      node(
        "div",
        claim.module + " · " + claim.status + " · " + claim.confidence + " · " + mapping,
        "claim-meta",
      ),
    );
    row.append(node("small", (claim.model_call_id ? "Model analysis · " : "Deterministic rules · ")
      + "Evidence: " + ((claim.evidence_ids || []).join(", ") || "none"), "claim-evidence"));
    container.append(row);
  });
}

function renderLimitations(limitations) {
  const block = byId("limitationBlock");
  const rows = byId("limitationRows");
  rows.replaceChildren();
  block.hidden = !limitations.length;
  limitations.forEach((limitation) => rows.append(node("li", limitation)));
}

function renderEvidence(evidence) {
  const body = byId("evidenceRows");
  body.replaceChildren();
  evidence.forEach((item) => {
    const row = node("tr");
    row.append(node("td", item.module));
    row.append(node("td", item.kind));
    row.append(node("td", JSON.stringify(item.anchor)));
    const actionCell = node("td");
    const button = node("button", "查看");
    button.type = "button";
    button.addEventListener("click", async () => {
      const detail = await fetchJSON("/api/v1/evidence/" + item.id);
      byId("evidenceDetail").textContent = JSON.stringify(detail, null, 2);
    });
    actionCell.append(button);
    row.append(actionCell);
    body.append(row);
  });
}

async function loadAnalysisTrace(taskId) {
  const trace = await fetchJSON("/api/v1/tasks/" + taskId + "/analysis-trace");
  byId("traceDisclosure").textContent = trace.disclosure?.message || "结构化分析过程视图";
  byId("traceSummary").textContent =
    "状态 " + (trace.lifecycle || "") + " · 结果 " + (trace.outcome || "未计算")
    + " · 步骤 " + trace.steps.length + " · 关系 " + trace.links.length;
  renderPlanningSummary(trace.dynamic_planning || {});
  renderTraceSteps(trace.steps);
  populateTableBody(
    byId("traceLinkRows"),
    trace.links.map((link) => [
      link.from_type + ":" + link.from_id,
      link.relation,
      link.to_type + ":" + link.to_id,
    ]),
  );
}

function renderPlanningSummary(planning) {
  const state = byId("planningSummaryState");
  const actions = byId("planningActions");
  const rejected = byId("planningRejected");
  actions.replaceChildren();
  rejected.replaceChildren();
  if (!planning || !planning.status) {
    state.textContent = "No model plan recorded; deterministic baseline was used.";
    return;
  }
  const history = planning.history || [];
  state.textContent = [
    "status=" + planning.status,
    "phase=" + (planning.phase || "-"),
    "rounds=" + history.length,
    "completed=" + (planning.completed_actions || []).length,
  ].join(" · ");
  (planning.actions || []).forEach((action) => {
    const item = node("div", null, "planning-action");
    item.append(
      node("strong", action.tool_name + " → " + action.target_artifact_id),
      node("span", "priority=" + action.priority + " · " + (action.reason || "")),
    );
    actions.append(item);
  });
  if (history.length) {
    actions.append(node("strong", "Model analysis rounds"));
    history.forEach((round) => {
      actions.append(node(
        "div",
        (round.phase || "round") + " · " + (round.status || "")
          + " · actions=" + (round.actions || []).length
          + " · completed=" + (round.completed_actions || []).length
          + (round.model_call_id ? " · model_call=" + round.model_call_id : ""),
        "planning-history",
      ));
    });
  }
  const rejectedActions = planning.rejected_actions || [];
  if (rejectedActions.length) {
    rejected.textContent = "Rejected by policy: " + rejectedActions.length;
    rejectedActions.forEach((item) => {
      rejected.append(node("div", item.reason || "invalid action"));
    });
  }
}

function renderTraceSteps(steps) {
  const container = byId("traceSteps");
  container.replaceChildren();
  if (!steps.length) {
    container.append(node("p", "尚未记录分析过程事件。"));
    return;
  }
  steps.forEach((step) => {
    const row = node("article", null, "trace-step");
    const heading = node("div", null, "trace-step-heading");
    heading.append(
      node("span", String(step.sequence ?? "-"), "trace-sequence"),
      node("strong", step.summary),
      node("span", step.phase + " · " + (step.actor || "system"), "trace-meta"),
    );
    row.append(heading);
    const refs = step.references || {};
    const referenceText = [
      ...(refs.tool_run_ids || []).map((id) => "ToolRun " + id),
      ...(refs.evidence_ids || []).map((id) => "Evidence " + id),
      ...(refs.claim_ids || []).map((id) => "Claim " + id),
      ...(refs.model_call_ids || []).map((id) => "ModelCall " + id),
    ];
    if (referenceText.length) {
      row.append(node("div", referenceText.join(" · "), "trace-references"));
    }
    const details = step.details || {};
    const detailText = Object.entries(details)
      .map(([key, value]) => key + "=" + String(value))
      .join(" · ");
    if (detailText) {
      row.append(node("div", detailText, "trace-details"));
    }
    container.append(row);
  });
}

async function loadReport(revisionId) {
  const report = await fetchJSON("/api/v1/reports/" + revisionId);
  state.revisionId = report.id;
  byId("reportEditor").value = report.markdown;
  updateDownloads(report.id);
}

function updateDownloads(revisionId) {
  const links = [
    ["downloadMd", "markdown"],
    ["downloadDocx", "docx"],
    ["downloadPdf", "pdf"],
  ];
  links.forEach(([id, format]) => {
    byId(id).href = revisionId
      ? "/api/v1/reports/" + revisionId + "/download?format=" + format
      : "#";
  });
  byId("downloadJson").href = state.taskId
    ? "/api/v1/tasks/" + state.taskId + "/analysis-package"
    : "#";
}

byId("recomposeButton").addEventListener("click", async () => {
  if (!state.taskId) {
    return;
  }
  const report = await fetchJSON("/api/v1/tasks/" + state.taskId + "/reports", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ modules: selectedModules() }),
  });
  await loadReport(report.id);
});

byId("saveEditButton").addEventListener("click", async () => {
  if (!state.revisionId) {
    return;
  }
  const report = await fetchJSON("/api/v1/reports/" + state.revisionId + "/edits", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      markdown: byId("reportEditor").value,
      author: "demo-analyst",
    }),
  });
  await loadReport(report.id);
});

initialize().catch((error) => {
  byId("systemState").textContent = error.message;
  document.querySelector(".state-dot").style.background = "#c5473a";
});
