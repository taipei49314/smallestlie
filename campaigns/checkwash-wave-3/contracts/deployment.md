# Frozen W3 deployment and measurement contract

Original maps and restoration provenance are in installations/. Reacquire the
immutable Git commit/tree and raw blobs; archive EOL filters are not original
bytes. Authenticate every part length/hash and declared order, the whole image
ZIP hash, and the complete restored map. Reject unsafe/duplicate/case-alias
names, links/reparse points and unused parts. Restore regular files into fresh
private roots. Do not reinstall, resolve packages or regenerate formal locks.

Python is the full sealed CPython3.12.10 prefix with locked pytest9.1.1.
Actual sys.executable is prefix/python.exe; sys.prefix and sys.base_prefix equal
the restored prefix. Its full map includes bytecode. Every action checks this
private receiver before claims and after work. Start with private python.exe
-I -B and an independently accepted launcher loading only frozen src/smallestlie
and contracts outside the prefix. No product install, ambient site, PYTHONPATH,
.pth trick or new bytecode. Launcher/loader acceptance is an external fact.

Each Node action has a fresh resolver containing original sealed package.json,
package-lock.json and complete node_modules, plus one literal fixture child.
Before materialization the child is absent. It alone is projected from the
logical JS installation map; the physical parent map is not claimed unchanged.
Reject extra top-level inputs and empty/unbound installation directories.

Bare Mocha/Chai/Vitest imports resolve through real parent node_modules.
No junction/symlink/hardlink, NODE_PATH/NODE_OPTIONS or resolver alias.
B1 self-reference uses the fixture's victim package/exports. The twin changes
both import and mock specifiers. The standalone Node image is separate and
protected. Only after its full map and actual node.exe bytes agree may original
native --version stdout supply the version metadata.

Vitest uses the same native-loader config in all arms, one fork worker,
fileParallelism false and JUnit inside fixture; it avoids bundled-config
.vite-temp writes into the installation. D1 selects both files with Mocha
config/package discovery disabled. D2 uses isolated Python, explicit pyproject,
disabled plugin autoload and cache.

Canonical map SHA uses sorted-key ASCII JSON with comma/colon separators.
Python runner identity is the outer complete pytest/_pytest maps; installed
identity is the full prefix map. JS runner identity is its complete package
map; installed identity is the full logical metadata/node_modules map.
Runtime identity is the raw executable hash, not download archive hash.
The intended profile labels cannot authenticate a live installation.

Output, claims, source and protected images are separate. Only the exact Node
fixture child sits inside its resolver. Verifier baseline/attack/command roots
are independent from runner roots/images. Explicit MinGit comes from a freshly
accepted EC generation, with cmd/git.exe or bin/git.exe two-level layout.
Record/check full image before/after native children and actual version.
Preparation did not measure/adopt that image; never fabricate its executable SHA.

ProducerBounds defaults: 30 seconds per child, 1MB output capture/report,
10MB fixture, 100MB Python installation, 5 seconds cleanup. Node/MinGit maps
have 256MiB bounds, JS 512MiB. Git child count is capped at 32. External workload
must enforce total time/disk, isolation and protected storage. File-map checks
and environment scrubbing are not OS network/ACL/power-loss guarantees.

NOT_RUN: restoration, receiver and case qualification need a later exact
separately authorized bounded pool workload.
