/**
 * fff-daemon client for Node/Bun over Unix Domain Socket.
 *
 * Uses synchronous fd-level I/O so that all FileFinder methods can remain
 * synchronous (the pi-fff extension API requires this).
 *
 * Speaks the same length-prefixed MessagePack protocol as the Rust client.
 */

import { execFileSync } from "child_process";
import { encode, decode } from "@msgpack/msgpack";
import net from "net";
import { tmpdir } from "os";
import { join } from "path";
import { existsSync, readSync, writeSync } from "fs";

import type {
  GrepResult,
  GrepMatch,
  HealthCheck,
  Result,
  ScanProgress,
  SearchResult,
  FileItem,
  Score,
} from "@ff-labs/fff-node";

// ---------------------------------------------------------------------------
// Socket path (must match fff-protocol's socket_path())
// ---------------------------------------------------------------------------

function daemonSocketPath(): string {
  if (process.platform === "linux" && process.env.XDG_RUNTIME_DIR) {
    return join(process.env.XDG_RUNTIME_DIR, "fff", "fff.sock");
  }
  const uid = process.getuid?.() ?? 0;
  return join(tmpdir(), `fff-${uid}`, "fff.sock");
}

// ---------------------------------------------------------------------------
// Synchronous UDS connection
//
// Node's net module only offers async connect. We async-connect, extract
// the raw fd from the internal _handle, then do all I/O with
// fs.readSync / fs.writeSync so the caller stays synchronous.
// ---------------------------------------------------------------------------

interface SyncSocket {
  fd: number;
  close(): void;
}

function connectSyncSocket(socketPath: string): SyncSocket {

  let fd = -1;
  let connected = false;
  let connectError: Error | null = null;

  const socket = net.createConnection(socketPath, () => {
    connected = true;
  });

  socket.once("error", (err: Error) => {
    connectError = err;
    connected = true;
  });

  const deadline = Date.now() + 5000;
  while (!connected && Date.now() < deadline) {
    try {
      execFileSync("sleep", ["0.001"], { stdio: "ignore" });
    } catch {}
    if ((socket as any)._handle && (socket as any)._handle.fd >= 0) {
      connected = true;
    }
  }

  if (connectError) throw connectError;

  const handle = (socket as any)._handle;
  if (!handle || handle.fd === undefined || handle.fd < 0) {
    fd = (socket as any).fd ?? -1;
    if (fd < 0) {
      socket.destroy();
      throw new Error("could not get socket fd");
    }
  } else {
    fd = handle.fd;
  }

  // Stop Node's internal read loop and set blocking mode so
  // readSync/writeSync block in the kernel instead of returning EAGAIN.
  socket.pause();
  if (handle && handle.reading) {
    handle.readStop();
  }
  if (typeof handle?.setBlocking === "function") {
    handle.setBlocking(true);
  }

  return {
    fd,
    close() {
      socket.destroy();
    },
  };
}

// ---------------------------------------------------------------------------
// Synchronous framed I/O on a raw fd
//
// When setBlocking(true) succeeded, reads/writes block in the kernel.
// Fallback: if the fd is still non-blocking (Bun), retry on EAGAIN.
// ---------------------------------------------------------------------------

function writeFd(fd: number, data: Buffer): void {
  let offset = 0;
  const deadline = Date.now() + 30000;
  while (offset < data.length) {
    let written: number;
    try {
      written = writeSync(fd, data, offset, data.length - offset);
    } catch (e: any) {
      if (e.code === "EAGAIN" || e.code === "EWOULDBLOCK") {
        if (Date.now() > deadline) throw new Error("write timed out");
        try { execFileSync("sleep", ["0.001"], { stdio: "ignore" }); } catch {}
        continue;
      }
      throw e;
    }
    if (written <= 0) throw new Error("write failed");
    offset += written;
  }
}

function readFdExact(fd: number, length: number): Buffer {
  const buf = Buffer.alloc(length);
  let offset = 0;
  const deadline = Date.now() + 30000;
  while (offset < length) {
    let n: number;
    try {
      n = readSync(fd, buf, offset, length - offset, null);
    } catch (e: any) {
      if (e.code === "EAGAIN" || e.code === "EWOULDBLOCK") {
        if (Date.now() > deadline) throw new Error("read timed out");
        try { execFileSync("sleep", ["0.001"], { stdio: "ignore" }); } catch {}
        continue;
      }
      throw e;
    }
    if (n <= 0) throw new Error("read failed / connection closed");
    offset += n;
  }
  return buf;
}

function sendFrame(fd: number, data: Uint8Array): void {
  const header = Buffer.alloc(4);
  header.writeUInt32BE(data.length, 0);
  writeFd(fd, header);
  writeFd(fd, Buffer.from(data));
}

function recvFrame(fd: number): Uint8Array {
  const header = readFdExact(fd, 4);
  const len = header.readUInt32BE(0);
  if (len > 64 * 1024 * 1024) throw new Error(`frame too large: ${len}`);
  const payload = readFdExact(fd, len);
  return new Uint8Array(payload);
}

// ---------------------------------------------------------------------------
// DaemonClient — synchronous request/response over UDS
// ---------------------------------------------------------------------------

class DaemonClient {
  private sock: SyncSocket | null = null;

  connect(socketPath: string): void {
    this.sock = connectSyncSocket(socketPath);
  }

  send(request: any): any {
    if (!this.sock) throw new Error("not connected");
    const payload = encode(request);
    sendFrame(this.sock.fd, payload);
    const respData = recvFrame(this.sock.fd);
    const resp = decode(respData) as any;

    if (typeof resp === "string") return resp;
    if (resp && typeof resp === "object" && "Error" in resp) {
      throw new Error(resp.Error);
    }
    return resp;
  }

  close(): void {
    if (this.sock) {
      this.sock.close();
      this.sock = null;
    }
  }

  get connected(): boolean {
    return this.sock !== null;
  }
}

// ---------------------------------------------------------------------------
// Wire → domain type converters
//
// rmp_serde::to_vec serializes structs as positional msgpack arrays.
// Field order must match the Rust struct definitions in fff-protocol.
// ---------------------------------------------------------------------------

// FileItemWire: [relative_path, name, size, modified, access_frecency_score,
//   modification_frecency_score, total_frecency_score, git_status, is_binary]
function wireToFileItem(w: any): FileItem {
  return {
    path: w[0],
    relativePath: w[0],
    fileName: w[1],
    size: w[2],
    modified: w[3],
    accessFrecencyScore: w[4],
    modificationFrecencyScore: w[5],
    totalFrecencyScore: w[6],
    gitStatus: w[7],
  };
}

// ScoreWire: [total, base_score, filename_bonus, special_filename_bonus,
//   frecency_boost, git_status_boost, distance_penalty, current_file_penalty,
//   combo_match_boost, path_alignment_bonus, exact_match, match_type]
function wireToScore(w: any): Score {
  return {
    total: w[0],
    baseScore: w[1],
    filenameBonus: w[2],
    specialFilenameBonus: w[3],
    frecencyBoost: w[4],
    distancePenalty: w[6],
    currentFilePenalty: w[7],
    comboMatchBoost: w[8],
    exactMatch: w[10],
    matchType: w[11],
  };
}

// GrepMatchWire: [relative_path, name, is_binary, git_status, size, modified,
//   total_frecency_score, access_frecency_score, modification_frecency_score,
//   line_number, col, byte_offset, line_content, match_ranges, fuzzy_score]
function wireToGrepMatch(w: any): GrepMatch {
  return {
    path: w[0],
    relativePath: w[0],
    fileName: w[1],
    isBinary: w[2],
    gitStatus: w[3],
    size: w[4],
    modified: w[5],
    totalFrecencyScore: w[6],
    accessFrecencyScore: w[7],
    modificationFrecencyScore: w[8],
    lineNumber: w[9],
    col: w[10],
    byteOffset: w[11],
    lineContent: w[12],
    matchRanges: w[13] ?? [],
    fuzzyScore: w[14],
  };
}

// ---------------------------------------------------------------------------
// DaemonFileFinder — drop-in replacement for FileFinder via daemon
// ---------------------------------------------------------------------------

export class DaemonFileFinder {
  private client: DaemonClient;
  private basePath: string;
  private _destroyed = false;

  private constructor(client: DaemonClient, basePath: string) {
    this.client = client;
    this.basePath = basePath;
  }

  static async tryCreate(options: {
    basePath: string;
    frecencyDbPath?: string;
    historyDbPath?: string;
    useUnsafeNoLock?: boolean;
    watchGitEvents?: boolean;
  }): Promise<Result<DaemonFileFinder>> {
    const socketPath = daemonSocketPath();
    if (!existsSync(socketPath)) {
      return { ok: false, error: "daemon socket not found" };
    }

    const client = new DaemonClient();
    try {
      client.connect(socketPath);
    } catch (e: any) {
      return { ok: false, error: `failed to connect to daemon: ${e.message}` };
    }

    try {
      client.send("Ping");

      if (options.frecencyDbPath || options.historyDbPath) {
        client.send({
          InitDb: {
            frecency_db_path: options.frecencyDbPath ?? "",
            history_db_path: options.historyDbPath ?? "",
            use_unsafe_no_lock: options.useUnsafeNoLock ?? false,
          },
        });
      }

      client.send({
        IndexDirectory: {
          path: options.basePath,
          watch_git_events: options.watchGitEvents ?? false,
        },
      });

      return { ok: true, value: new DaemonFileFinder(client, options.basePath) };
    } catch (e: any) {
      client.close();
      return { ok: false, error: `daemon init failed: ${e.message}` };
    }
  }

  destroy(): void {
    if (!this._destroyed) {
      try {
        this.client.send({ CleanupFilePicker: { path: this.basePath } });
      } catch {}
      this.client.close();
      this._destroyed = true;
    }
  }

  get isDestroyed(): boolean {
    return this._destroyed;
  }

  fileSearch(query: string, options?: { pageSize?: number; currentFile?: string; maxThreads?: number; comboBoostMultiplier?: number; minComboCount?: number; pageIndex?: number }): Result<SearchResult> {
    try {
      const resp = this.client.send({
        FuzzySearch: {
          path: this.basePath,
          query,
          max_threads: options?.maxThreads ?? 0,
          current_file: options?.currentFile ?? null,
          combo_boost_score_multiplier: options?.comboBoostMultiplier ?? 0,
          min_combo_count: options?.minComboCount ?? 3,
          page_index: options?.pageIndex ?? 0,
          page_size: options?.pageSize ?? 0,
        },
      });
      // SearchResultWire: [items, scores, total_matched, total_files, location]
      const r = resp.SearchResult;
      return {
        ok: true,
        value: {
          items: (r[0] ?? []).map(wireToFileItem),
          scores: (r[1] ?? []).map(wireToScore),
          totalMatched: r[2],
          totalFiles: r[3],
          location: r[4],
        } as SearchResult,
      };
    } catch (e: any) {
      return { ok: false, error: e.message };
    }
  }

  grep(query: string, options?: { mode?: string; smartCase?: boolean; maxMatchesPerFile?: number; cursor?: any; timeBudgetMs?: number; beforeContext?: number; afterContext?: number }): Result<GrepResult> {
    try {
      const fileOffset = options?.cursor?._offset ?? 0;
      const resp = this.client.send({
        GrepSearch: {
          path: this.basePath,
          query,
          file_offset: fileOffset,
          page_size: 50,
          max_file_size: 10 * 1024 * 1024,
          max_matches_per_file: options?.maxMatchesPerFile ?? 200,
          smart_case: options?.smartCase ?? true,
          grep_mode: options?.mode === "regex" ? "Regex" : options?.mode === "fuzzy" ? "Fuzzy" : "PlainText",
          time_budget_ms: options?.timeBudgetMs ?? 0,
          trim_whitespace: false,
        },
      });
      // GrepResultWire: [items, total_matched, total_files_searched,
      //   total_files, filtered_file_count, next_file_offset, regex_fallback_error]
      const r = resp.GrepResult;
      return {
        ok: true,
        value: {
          items: (r[0] ?? []).map(wireToGrepMatch),
          totalMatched: r[1],
          totalFilesSearched: r[2],
          totalFiles: r[3],
          filteredFileCount: r[4],
          nextCursor: r[5] > 0 ? { __brand: "GrepCursor" as const, _offset: r[5] } : null,
          regexFallbackError: r[6],
        } as GrepResult,
      };
    } catch (e: any) {
      return { ok: false, error: e.message };
    }
  }

  multiGrep(options: { patterns: string[]; constraints?: string; maxMatchesPerFile?: number; smartCase?: boolean; cursor?: any; timeBudgetMs?: number; beforeContext?: number; afterContext?: number }): Result<GrepResult> {
    const query = (options.constraints ? options.constraints + " " : "") + options.patterns.join("|");
    return this.grep(query, {
      mode: "plain",
      smartCase: options.smartCase ?? true,
      maxMatchesPerFile: options.maxMatchesPerFile,
      cursor: options.cursor,
      timeBudgetMs: options.timeBudgetMs,
    });
  }

  scanFiles(): Result<void> {
    try {
      this.client.send({ TriggerRescan: { path: this.basePath } });
      return { ok: true, value: undefined };
    } catch (e: any) {
      return { ok: false, error: e.message };
    }
  }

  isScanning(): boolean {
    try {
      const r = this.client.send({ IsScanning: { path: this.basePath } });
      return r.Bool ?? false;
    } catch {
      return false;
    }
  }

  getScanProgress(): Result<ScanProgress> {
    try {
      // ScanProgressWire: [scanned_files_count, is_scanning]
      const r = this.client.send({ GetScanProgress: { path: this.basePath } });
      const p = r.ScanProgress;
      return { ok: true, value: { scannedFilesCount: p[0], isScanning: p[1] } };
    } catch (e: any) {
      return { ok: false, error: e.message };
    }
  }

  async waitForScan(timeoutMs: number = 5000): Promise<Result<boolean>> {
    try {
      const resp = this.client.send({ WaitForScan: { path: this.basePath, timeout_ms: timeoutMs } });
      return { ok: true, value: resp.Bool ?? true };
    } catch (e: any) {
      return { ok: false, error: e.message };
    }
  }

  reindex(newPath: string): Result<void> {
    try {
      const oldPath = this.basePath;
      this.basePath = newPath;
      this.client.send({ RestartIndex: { path: oldPath, new_path: newPath } });
      return { ok: true, value: undefined };
    } catch (e: any) {
      return { ok: false, error: e.message };
    }
  }

  refreshGitStatus(): Result<number> {
    try {
      const r = this.client.send({ RefreshGitStatus: { path: this.basePath } });
      return { ok: true, value: r.Usize ?? 0 };
    } catch (e: any) {
      return { ok: false, error: e.message };
    }
  }

  trackQuery(query: string, selectedFilePath: string): Result<boolean> {
    try {
      const r = this.client.send({ TrackQueryCompletion: { path: this.basePath, query, file_path: selectedFilePath } });
      return { ok: true, value: r.Bool ?? true };
    } catch (e: any) {
      return { ok: false, error: e.message };
    }
  }

  getHistoricalQuery(offset: number): Result<string | null> {
    try {
      const r = this.client.send({ GetHistoricalQuery: { path: this.basePath, offset } });
      return { ok: true, value: r.OptionalString ?? null };
    } catch (e: any) {
      return { ok: false, error: e.message };
    }
  }

  healthCheck(testPath?: string): Result<HealthCheck> {
    try {
      // HealthCheckWire: [version, git_available, git_repository_found,
      //   git_libgit2_version, git_workdir, file_picker_initialized,
      //   file_picker_base_path, file_picker_is_scanning, file_picker_indexed_files]
      const r = this.client.send({ HealthCheck: { path: testPath || this.basePath } });
      const h = r.HealthCheck;
      return {
        ok: true,
        value: {
          version: h[0],
          git: {
            available: h[1],
            repositoryFound: h[2],
            libgit2Version: h[3],
            workdir: h[4],
          },
          filePicker: {
            initialized: h[5],
            basePath: h[6],
            isScanning: h[7],
            indexedFiles: h[8],
          },
          frecency: { initialized: true },
          queryTracker: { initialized: true },
        } as HealthCheck,
      };
    } catch (e: any) {
      return { ok: false, error: e.message };
    }
  }
}

/**
 * Check if the fff-daemon is available (socket exists).
 */
export function isDaemonAvailable(): boolean {
  return existsSync(daemonSocketPath());
}
