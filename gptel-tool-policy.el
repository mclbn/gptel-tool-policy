;;; gptel-tool-policy.el --- Path-based security policy for gptel tool calls -*- lexical-binding: t; -*-

;; A path-based security policy layer for filesystem tools invoked through
;; gptel.  It installs a single function on `gptel-pre-tool-call-functions'
;; and enforces ordered allow / deny / ask rules against normalized paths.
;; Tools named in the bypass list are exempt: they skip the policy entirely.
;;
;; Quick start:
;;
;;   (with-eval-after-load 'gptel
;;     (load "/path/to/gptel-tool-policy.el")
;;     (gptel-tool-policy-mode 1))
;;
;; Loading the file arms the policy by itself, so the explicit call above is
;; belt and braces.  Set `gptel-tool-policy-enable-on-load' to nil *before*
;; loading if you would rather arm it yourself.
;;
;; Interactive commands:
;;
;;   M-x gptel-tool-policy-add-rule        add a rule (action/class/scope)
;;   M-x gptel-tool-policy-whitelist-cwd   allow the current directory
;;   M-x gptel-tool-policy-whitelist-path  allow one path
;;   M-x gptel-tool-policy-remove-rule     remove a single session rule
;;   M-x gptel-tool-policy-clear-rules     clear a scope's session rules
;;   M-x gptel-tool-policy-add-bypass      exempt one tool from the policy
;;   M-x gptel-tool-policy-show-rules      show the effective rule set
;;
;; Rule format: (ACTION CLASS PATTERN COMMENT)
;;
;;   (deny  read  "~/.ssh/**"     "Never expose SSH keys")
;;   (allow write "~/projects/**" "Write project files")
;;   (ask   read  "~/**"          "Ask elsewhere in $HOME")
;;
;; Patterns: "DIR/**" recursive match, "PREFIX*" prefix match, otherwise
;; exact match.  A "*" anywhere else makes the rule malformed: it is refused
;; by `gptel-tool-policy-add-rule', flagged by `gptel-tool-policy-show-rules'
;; and ignored.  Glob patterns such as "~/**/*.pem" are not supported; real
;; glob matching would be a welcome future addition.  Rules are evaluated in
;; order; the first match wins, so place denies for dangerous paths before
;; broader allows.
;;
;; Components:
;;
;;   * Bypass list -- the first thing the hook consults.  A tool whose name
;;     appears in `gptel-tool-policy-bypass-tools' (defcustom, persistent) or
;;     in `gptel-tool-policy-global-bypass-tools' (session-only) is exempt
;;     from the policy: the hook returns nil at once, with no path
;;     extraction, no registry lookup, no rule evaluation and no
;;     confirmation.  The two layers are a disjunction -- presence in either
;;     is enough -- so unlike rules, they carry no precedence and their order
;;     is immaterial.  Add to the session layer with
;;     `gptel-tool-policy-add-bypass'.  This is unconditional trust; see the
;;     docstring of `gptel-tool-policy-bypass-tools' before using it.
;;
;;   * Tool registry -- `gptel-tool-policy-tool-registry' maps a tool name to
;;     a plist (:class CLASS :extractor FUNCTION).  CLASS is an operation
;;     class keyword symbol (`read' or `write'); EXTRACTOR takes the tool
;;     call's :args and returns a list of path strings.  Adding a new tool
;;     source means adding registry entries (see
;;     `gptel-tool-policy-register-tool'), not touching the engine.
;;
;;   * Policy engine -- normalizes each extracted path (expand-file-name,
;;     file-truename, Tramp prefix stripped) and evaluates the effective rule
;;     list first-match-wins across three layers:
;;
;;         buffer-local session rules
;;       → global session rules
;;       → `gptel-tool-policy-rules' (defcustom, the only persistent layer)
;;
;;     If any checked path is denied, the whole call is blocked with
;;     `(:block MESSAGE)'.  Otherwise, if any path asks, `(:confirm t)' is
;;     returned and gptel's own confirmation overlay handles it.  Only when
;;     every path is allowed does the hook return `(:confirm nil)', which
;;     also overrides the :confirm slot of tools that ask by themselves.
;;
;;     Symlinks: the truename of each path is what gets decided.  A rule
;;     naming a path through a symlink still denies or asks for that path
;;     as written, but an allow rule must name the real location; the
;;     interactive commands resolve symlinks for you.  A directory is
;;     checked as a tree: a deny or ask rule anchored inside it applies to
;;     the whole call, since Grep, Glob and Edit diffs reach all of it.
;;
;;     Paths are expanded in the tool call's own buffer, so a relative path
;;     (Glob's default ".", a relative Edit path) resolves against that buffer's
;;     `default-directory' rather than whatever buffer happens to be current
;;     when the hook runs.
;;
;;   * Interactive commands -- `gptel-tool-policy-add-rule',
;;     `gptel-tool-policy-whitelist-cwd', `gptel-tool-policy-whitelist-path',
;;     `gptel-tool-policy-remove-rule', `gptel-tool-policy-clear-rules',
;;     `gptel-tool-policy-add-bypass' and
;;     `gptel-tool-policy-show-rules'.  All additions are session-only and
;;     are prepended to the front of their layer; the defcustom is never
;;     modified.  `gptel-tool-policy-whitelist-path' treats a trailing "/"
;;     as a directory, so a not-yet-created directory still gets "/**".
;;     `gptel-tool-policy-show-rules' reports a per-layer rule count.
;;
;; Design constraints (by design):
;;
;;   * The Bash tool is not covered.  MCP filesystem tools are out of scope.
;;     gptel only runs `gptel-pre-tool-call-functions' for requests whose
;;     state machine has a TPRE state: `gptel-send', gptel-rewrite and
;;     gptel-agent sub-agents.  A plain `gptel-request' call with tools
;;     skips the hook, and so the policy.
;;     Tramp matching applies to the local part of a remote path only (with
;;     a warning).
;;
;;   * Defcustoms intentionally omit `:safe' predicates.  A `:safe'
;;     predicate would let any project's .dir-locals.el silently replace the
;;     policy, handing the kill switch to the material the policy exists to
;;     guard against.  Rules must come from your own init file or a session
;;     command.  This holds for the bypass list too, which is a kill switch
;;     by definition.
;;
;;   * The bypass list is purely name-based and unconditional.  It inspects
;;     neither the tool's behaviour nor its arguments, and it outranks the
;;     whole policy -- the registry and every rule in every layer, including
;;     the denies shipped in `gptel-tool-policy-rules'.  It is meant for
;;     tools that never touch the filesystem, or that you trust without
;;     reservation.  There is deliberately no per-class or per-pattern
;;     bypass: that granularity belongs in a rule.
;;
;;   * A bypass layer whose value is not a proper list grants no bypass at
;;     all, rather than granting one by accident -- an improper list makes
;;     `member' return a match for any name before the malformed tail.  Such
;;     a value is reported once at load time by
;;     `gptel-tool-policy--validate-bypass-lists'; a value assigned after
;;     load is not seen by that pass, and simply has no effect.

;;; Code:

(require 'seq)
(require 'subr-x)

(defvar gptel-pre-tool-call-functions)

;; Completion sources for `gptel-tool-policy-add-bypass', declared here so
;; that the byte compiler stays quiet whether or not gptel is loaded.
;; `gptel--known-tools' is documented by gptel as internal; it is the only
;; way to enumerate tools that are registered but not enabled, and every read
;; of it is guarded and falls back to the public `gptel-tools' -- see
;; `gptel-tool-policy--known-tool-names'.
(defvar gptel--known-tools)
(defvar gptel-tools)
(declare-function gptel-tool-name "gptel" (tool))


;;;; Configuration

(defgroup gptel-tool-policy nil
  "Path-based security policy for gptel tool calls."
  :group 'gptel
  :group 'tools
  :prefix "gptel-tool-policy-")

(defvar gptel-tool-policy-enable-on-load t
  "When non-nil, loading this file turns `gptel-tool-policy-mode' on.
Set this to nil *before* loading if you prefer to arm the policy yourself;
`defvar' will not clobber a value you have already set.")

(defcustom gptel-tool-policy-rules
  '((deny  read  "~/.ssh/**"       "Never expose SSH keys")
    (deny  write "~/.ssh/**"       "Never write inside ~/.ssh")
    (deny  read  "~/.gnupg/**"     "Never expose GPG keys")
    (deny  write "~/.gnupg/**"     "Never write inside ~/.gnupg")
    (deny  read  "~/.authinfo*"    "Never expose stored credentials")
    (deny  write "~/.authinfo*"    "Never write stored credentials")
    (deny  read  "~/.netrc"        "Never expose stored credentials")
    (deny  write "~/.netrc"        "Never write stored credentials"))
  "Base policy rules, evaluated last and the only persistent layer.

Each rule is a list (ACTION CLASS PATTERN COMMENT):

ACTION  one of the symbols `allow', `deny' or `ask'.
CLASS   the operation class the rule applies to, `read' or `write'.
        The class field is mandatory; there are no class-less rules.
PATTERN a path pattern.  \"DIR/**\" matches DIR and everything below it,
        \"PREFIX*\" matches any path starting with PREFIX, anything else
        is an exact path match.  \"~\" and relative parts are expanded
        before matching.  A \"*\" anywhere else makes the rule
        malformed, and it is ignored: glob patterns are not supported.
COMMENT a descriptive string, shown by `gptel-tool-policy-show-rules' and
        used by the `detailed' deny message.

Rules are evaluated in order and the first match wins, so place denies for
dangerous paths before broader allows."
  :type '(repeat
          (list (choice :tag "Action"
                        (const :tag "Allow" allow)
                        (const :tag "Deny"  deny)
                        (const :tag "Ask"   ask))
                (choice :tag "Class"
                        (const :tag "Read"  read)
                        (const :tag "Write" write)
                        (symbol :tag "Other operation class"))
                (string :tag "Path pattern")
                (string :tag "Comment")))
  :group 'gptel-tool-policy)

(defcustom gptel-tool-policy-default-action 'ask
  "Action taken when no rule matches a checked path."
  :type '(choice (const :tag "Ask for confirmation" ask)
                 (const :tag "Block the call" deny)
                 (const :tag "Let the call proceed" allow))
  :group 'gptel-tool-policy)

(defcustom gptel-tool-policy-deny-message 'generic
  "Content of the message returned to the LLM when a call is denied.

`generic'   a fixed string revealing neither path nor rule (default);
            this avoids handing filesystem-layout intelligence to a
            possibly adversarial model.
`detailed'  the matched path plus the matching rule's comment, which lets
            a trusted model correct itself.
STRING      that string, used verbatim."
  :type '(choice (const :tag "Generic, no details" generic)
                 (const :tag "Detailed: path and rule comment" detailed)
                 (string :tag "Custom message"))
  :group 'gptel-tool-policy)

(defconst gptel-tool-policy-generic-deny-message
  "This tool call was blocked by the local security policy."
  "Fixed string used when `gptel-tool-policy-deny-message' is `generic'.")


;;;; Session-only rule layers

(defvar-local gptel-tool-policy-buffer-rules nil
  "Buffer-local session rules, consulted before all other layers.
Session-only: never persisted.  Managed by the interactive commands.")

(defvar gptel-tool-policy-global-rules nil
  "Global session rules, consulted after buffer-local rules.
Session-only: never persisted.  Managed by the interactive commands.")


;;;; Tool bypass list
;;
;; Two flat lists of tool names that skip the policy altogether.  Presence in
;; either one is enough: the check is a disjunction, not a layered lookup, so
;; unlike the rule engine -- where first-match-wins makes order load-bearing --
;; the order the two are tested in means nothing.

(defcustom gptel-tool-policy-bypass-tools nil
  "Tool names exempted from the policy, the persistent bypass layer.

A flat list of tool name strings, compared with `equal' against the :name of
each tool call.  A tool named here is not policed at all: the hook returns
nil at once, before path extraction, before the registry lookup and before
any rule is evaluated, and gptel's own confirmation settings apply
\(`gptel-confirm-tool-calls' and the tool's :confirm slot).

Bypass outranks the entire policy, not merely the registry.  Every rule in
every layer is skipped, including the denies shipped in the default value of
`gptel-tool-policy-rules': with \"Read\" listed here, a Read of ~/.ssh/id_rsa
proceeds silently.  This is unconditional trust, granted by name alone, with
no inspection of what the tool does or of the arguments it was handed.
Reserve it for tools that cannot touch the filesystem, or that you trust
without reservation.  Anything narrower -- one operation class, one
directory -- belongs in `gptel-tool-policy-rules' as an `allow' rule, where
it stays visible and bounded.

`gptel-tool-policy-global-bypass-tools' is the session-only equivalent.  The
two are a disjunction: a name in either bypasses, so neither takes precedence
over the other and their order is immaterial.

Like every defcustom in this package, this one deliberately has no `:safe'
predicate.  A `:safe' predicate would let any project's .dir-locals.el add
entries here -- that is, let the material the policy exists to guard against
switch the policy off for the tools of its own choosing.  Set this in your
init file, or use \\[gptel-tool-policy-add-bypass] for the current session.

A value that is not a proper list grants no bypass at all, and is reported at
load time by `gptel-tool-policy--validate-bypass-lists'.  Non-string entries
in an otherwise well-formed list are harmless: they simply never match."
  :type '(repeat string)
  :group 'gptel-tool-policy)

(defvar gptel-tool-policy-global-bypass-tools nil
  "Tool names exempted from the policy for this session.
Session-only: never persisted.  Managed by `gptel-tool-policy-add-bypass'.
There is no clear command for a list this simple; reset it with
`setq' or by restarting Emacs.

Semantics, and the security implications, are those of
`gptel-tool-policy-bypass-tools' -- read that docstring before adding
anything here.  The two lists are a disjunction, so neither takes precedence
over the other.")

(defun gptel-tool-policy--bypassed-p (name)
  "Return non-nil when the tool called NAME is exempt from the policy.

NAME is exempt when it appears in `gptel-tool-policy-global-bypass-tools' or
in `gptel-tool-policy-bypass-tools'.  The test is a disjunction: the order
the two layers are examined in is not a precedence.

Each layer is guarded with `proper-list-p', which is load-bearing rather than
decorative.  `member' signals on an atom, but against an improper list such
as the dotted pair of \"Read\" and \"Grep\" it matches any name positioned
before the malformed tail and never reaches the error -- so an unguarded test
would let a broken configuration grant the bypass instead of withholding it.
A layer that is not a proper list contributes nothing, exactly as if it were
empty, and the call falls through to normal evaluation.

A NAME that is not a string is never exempt, so a tool call arriving without
a :name cannot be waved through by a stray nil in a list.

This runs on every tool call and is side-effect free by design: no warning,
no message, no state.  Malformed layers are diagnosed once at load time, by
`gptel-tool-policy--validate-bypass-lists'."
  (and (stringp name)
       (or (and (proper-list-p gptel-tool-policy-global-bypass-tools)
                (member name gptel-tool-policy-global-bypass-tools))
           (and (proper-list-p gptel-tool-policy-bypass-tools)
                (member name gptel-tool-policy-bypass-tools)))))

(defun gptel-tool-policy--validate-bypass-lists ()
  "Warn about each bypass variable whose value is not a proper list.

Return non-nil when both `gptel-tool-policy-bypass-tools' and
`gptel-tool-policy-global-bypass-tools' are well formed; otherwise return
nil, having emitted one warning per offending variable, naming it and showing
its value.

Called once when this file is loaded, independently of
`gptel-tool-policy-enable-on-load': a malformed configuration is worth
reporting whether or not the policy is armed.  That catches the realistic
authoring mistake, a typo'd list in an init file, but it cannot see a value
assigned afterwards by `setq' or through `customize'.  Such a value is still
harmless -- `gptel-tool-policy--bypassed-p' withholds the bypass either way --
but it will silently do nothing, so call this by hand if you want it checked."
  (let ((valid t))
    (dolist (symbol '(gptel-tool-policy-bypass-tools
                      gptel-tool-policy-global-bypass-tools))
      (let ((value (symbol-value symbol)))
        (unless (proper-list-p value)
          (setq valid nil)
          (display-warning
           'gptel-tool-policy
           (format
            "%s is not a proper list (%S); it grants no bypass and is ignored."
            symbol value)
           :warning))))
    valid))


;;;; Argument access helpers

(defun gptel-tool-policy--key-name (key)
  "Return the bare name of KEY, a keyword, symbol or string."
  (cond ((keywordp key) (substring (symbol-name key) 1))
        ((symbolp key) (symbol-name key))
        ((stringp key) (string-remove-prefix ":" key))
        (t (format "%s" key))))

(defun gptel-tool-policy--sym (value)
  "Coerce VALUE to a bare symbol, tolerating keywords and strings."
  (cond ((null value) nil)
        ((keywordp value) (intern (substring (symbol-name value) 1)))
        ((symbolp value) value)
        ((stringp value) (intern (downcase (string-remove-prefix ":" value))))
        (t nil)))

(defun gptel-tool-policy--arg (args key)
  "Return the value of KEY in ARGS.
ARGS is normally a plist with keyword keys, but alists and string or plain
symbol keys are tolerated so that differently shaped tool arguments still
work.  This laxity is deliberate: a tool source that renames or reshapes its
arguments must not be able to slip a path past the policy by making it
unreadable.  Do not \"fix\" it into a plain `plist-get'."
  (let ((want (gptel-tool-policy--key-name key)))
    (cond
     ((not (consp args)) nil)
     ((consp (car args))
      (cdr (seq-find (lambda (cell)
                       (and (consp cell)
                            (equal want (gptel-tool-policy--key-name (car cell)))))
                     args)))
     (t
      (let ((tail args) (found nil) (result nil))
        (while (and tail (not found))
          (when (equal want (gptel-tool-policy--key-name (car tail)))
            (setq found t result (cadr tail)))
          (setq tail (cdr (cdr tail))))
        result)))))

(defun gptel-tool-policy--string-arg (args key)
  "Return the value of KEY in ARGS when it is a non-empty string.
The value is returned unchanged, whitespace included: the tool receives it
unchanged, so that is what the policy must check."
  (let ((value (gptel-tool-policy--arg args key)))
    (and (stringp value) (not (string-empty-p value)) value)))


;;;; Path extractors
;;
;; Contract: input is the tool call's :args, output is a list of path
;; strings (possibly empty).  Never a bare string, never nil.

(defun gptel-tool-policy--extract-key (args key)
  "Return the single path named by KEY in ARGS, as a list, or an empty list.
Shared by the extractors of tools that name exactly one path argument."
  (let ((path (gptel-tool-policy--string-arg args key)))
    (if path (list path) '())))

(defun gptel-tool-policy--extract-read (args)
  "Extract paths checked for a Read call from ARGS (:file_path)."
  (gptel-tool-policy--extract-key args :file_path))

(defun gptel-tool-policy--extract-grep (args)
  "Extract paths checked for a Grep call from ARGS (:path).
gptel-agent's Grep searches (substitute-in-file-name PATH), which expands
environment variables and restarts the path at \"//\" or \"/~\", so that
form is checked as well."
  (let ((path (gptel-tool-policy--string-arg args :path)))
    (if path (delete-dups (list path (substitute-in-file-name path))) '())))

(defun gptel-tool-policy--extract-glob (args)
  "Extract paths checked for a Glob call from ARGS (optional :path)."
  (list (or (gptel-tool-policy--string-arg args :path) ".")))

(defun gptel-tool-policy--extract-write (args)
  "Extract paths checked for a Write call from ARGS (:path plus :filename)."
  (let ((dir (gptel-tool-policy--string-arg args :path))
        (file (gptel-tool-policy--string-arg args :filename)))
    (cond ((and dir file) (list (expand-file-name file (file-name-as-directory dir))))
          (file (list file))
          (dir (list dir))
          (t '()))))

(defun gptel-tool-policy--extract-insert (args)
  "Extract paths checked for an Insert call from ARGS (:path)."
  (gptel-tool-policy--extract-key args :path))

(defun gptel-tool-policy--extract-mkdir (args)
  "Extract paths checked for a Mkdir call from ARGS (:parent plus :name)."
  (let ((parent (gptel-tool-policy--string-arg args :parent))
        (name (gptel-tool-policy--string-arg args :name)))
    (cond ((and parent name)
           (list (expand-file-name name (file-name-as-directory parent))))
          (name (list name))
          (parent (list parent))
          (t '()))))

(defun gptel-tool-policy--extract-edit (args)
  "Extract paths checked for an Edit call from ARGS.

:path is always checked.  gptel-agent replaces text only when :diff is
:json-false or :old_str is non-nil; any other call applies :new_str as a
diff, with \"patch\" run without -p in the directory of :path.  patch then
keeps only the basename of whichever header name it picks (\"---\",
\"+++\", \"Index:\", git headers, indented or quoted), and can create,
delete or rename files and create symlinks there.  So the headers say
nothing reliable, and the directory itself is checked instead; being a
directory, it is checked as a tree, see `gptel-tool-policy--decide-tree'."
  (let ((path (gptel-tool-policy--string-arg args :path))
        (diff (gptel-tool-policy--arg args :diff))
        (old-str (gptel-tool-policy--arg args :old_str)))
    (cond ((null path) '())
          ((or (eq diff :json-false) old-str) (list path))
          (t (list path (file-name-directory (expand-file-name path)))))))


;;;; Tool registry

(defvar gptel-tool-policy-tool-registry
  '(("Read"   . (:class read  :extractor gptel-tool-policy--extract-read))
    ("Grep"   . (:class read  :extractor gptel-tool-policy--extract-grep))
    ("Glob"   . (:class read  :extractor gptel-tool-policy--extract-glob))
    ("Write"  . (:class write :extractor gptel-tool-policy--extract-write))
    ("Insert" . (:class write :extractor gptel-tool-policy--extract-insert))
    ("Edit"   . (:class write :extractor gptel-tool-policy--extract-edit))
    ("Mkdir"  . (:class write :extractor gptel-tool-policy--extract-mkdir)))
  "Alist mapping a tool name to (:class CLASS :extractor FUNCTION).

CLASS is an operation class symbol; currently `read' and `write'.  A future
class (for example `execute' for a Bash tool) needs no engine change, only
rules mentioning that class.  EXTRACTOR receives the tool call's :args and
returns a list of path strings.

Covering a new tool source means adding entries here, e.g. via
`gptel-tool-policy-register-tool'.")

(defun gptel-tool-policy-register-tool (name class extractor)
  "Register tool NAME with operation CLASS and path EXTRACTOR.
An existing entry for NAME is replaced."
  (setf (alist-get name gptel-tool-policy-tool-registry nil nil #'equal)
        (list :class (gptel-tool-policy--sym class) :extractor extractor))
  gptel-tool-policy-tool-registry)

(defun gptel-tool-policy--registry-entry (name)
  "Return the registry entry for tool NAME, or nil."
  (and (stringp name)
       (cdr (assoc name gptel-tool-policy-tool-registry #'equal))))


;;;; Path normalization

(defun gptel-tool-policy--truename (path)
  "Return the truename of PATH, falling back to PATH on error."
  (condition-case nil
      (file-truename path)
    (error path)))

(defun gptel-tool-policy--path-candidates (path)
  "Return the normalized forms of PATH to match rules against.
Both the expanded path and its truename are returned (deduplicated), the
truename last; see `gptel-tool-policy--decide-path' for how each
counts.  A remote path warns and is reduced to its local part, unresolved."
  (let ((expanded (expand-file-name path)))
    (if (file-remote-p expanded)
        (progn
          (display-warning
           'gptel-tool-policy
           (format "Remote (Tramp) path %s: policy matching uses the local part only, and symlinks on the remote host are not resolved."
                   expanded)
           :warning)
          (list (file-local-name expanded)))
      (delete-dups (list expanded (gptel-tool-policy--truename expanded))))))


;;;; Pattern matching

(defun gptel-tool-policy--expand-pattern (pattern)
  "Expand PATTERN as a path, keeping any trailing partial component."
  (file-local-name (expand-file-name pattern)))

(defun gptel-tool-policy--string= (a b ignore-case)
  "Return non-nil when strings A and B are equal, ignoring case if IGNORE-CASE."
  (eq t (compare-strings a nil nil b nil nil ignore-case)))

(defun gptel-tool-policy--match-pattern (pattern path &optional ignore-case)
  "Return non-nil when PATTERN matches the normalized PATH.
\"DIR/**\" is checked first (recursive match of DIR and everything under
it), then \"PREFIX*\" (prefix match), then an exact path match.  With
IGNORE-CASE non-nil, letter case is not significant."
  (when (and (stringp pattern) (stringp path) (not (string-empty-p pattern)))
    (cond
     ;; 1. Recursive directory match.
     ((string-suffix-p "/**" pattern)
      (let* ((raw (substring pattern 0 -3))
             (base (directory-file-name
                    (if (string-empty-p raw)
                        "/"
                      (gptel-tool-policy--expand-pattern raw)))))
        (or (gptel-tool-policy--string= (directory-file-name path) base ignore-case)
            (string-prefix-p (file-name-as-directory base) path ignore-case))))
     ;; 2. Prefix match.
     ((string-suffix-p "*" pattern)
      (let ((prefix (substring pattern 0 -1)))
        (if (string-empty-p prefix)
            t
          (string-prefix-p (gptel-tool-policy--expand-pattern prefix) path
                           ignore-case))))
     ;; 3. Exact match.
     (t
      (gptel-tool-policy--string=
       (directory-file-name (gptel-tool-policy--expand-pattern pattern))
       (directory-file-name path)
       ignore-case)))))


;;;; Rule accessors and the effective rule list

(defun gptel-tool-policy--rule-action (rule)
  "Return the action symbol of RULE."
  (gptel-tool-policy--sym (nth 0 rule)))

(defun gptel-tool-policy--rule-class (rule)
  "Return the operation class symbol of RULE."
  (gptel-tool-policy--sym (nth 1 rule)))

(defun gptel-tool-policy--rule-pattern (rule)
  "Return the path pattern of RULE."
  (nth 2 rule))

(defun gptel-tool-policy--rule-comment (rule)
  "Return the comment of RULE, or nil."
  (let ((comment (nth 3 rule)))
    (and (stringp comment) (not (string-empty-p comment)) comment)))

(defun gptel-tool-policy--rule-valid-p (rule)
  "Return non-nil when RULE is well formed.
A pattern may contain \"*\" only as its \"/**\" or \"*\" ending.  Any
other \"*\" would be matched literally, so the rule would silently never
match; rejecting it lets `gptel-tool-policy-add-rule' refuse it and
`gptel-tool-policy-show-rules' flag it."
  ;; Supporting real glob patterns here would be a welcome future addition.
  (and (consp rule)
       (memq (gptel-tool-policy--rule-action rule) '(allow deny ask))
       (gptel-tool-policy--rule-class rule)
       (let ((pattern (gptel-tool-policy--rule-pattern rule)))
         (and (stringp pattern)
              (not (string-empty-p pattern))
              (not (string-match-p
                    "\\*" (replace-regexp-in-string
                           "\\(?:/\\*\\*\\|\\*\\)\\'" "" pattern)))))))

(defun gptel-tool-policy--rule-matches-p (rule class path)
  "Return non-nil when RULE covers CLASS and matches PATH.
`deny' and `ask' rules ignore letter case: on a case-insensitive filesystem
\"~/.SSH\" is \"~/.ssh\", and over-matching a restrictive rule is safe."
  (and (gptel-tool-policy--rule-valid-p rule)
       (eq (gptel-tool-policy--rule-class rule) class)
       (gptel-tool-policy--match-pattern
        (gptel-tool-policy--rule-pattern rule) path
        (not (eq (gptel-tool-policy--rule-action rule) 'allow)))))

(defun gptel-tool-policy--rule-anchor (rule)
  "Return the expanded path the pattern of the valid RULE is anchored at.
That is DIR for \"DIR/**\", PREFIX for \"PREFIX*\" and the path itself
for an exact pattern; nil for \"/**\" and \"*\", anchored nowhere."
  (let* ((pattern (gptel-tool-policy--rule-pattern rule))
         (raw (cond ((string-suffix-p "/**" pattern) (substring pattern 0 -3))
                    ((string-suffix-p "*" pattern) (substring pattern 0 -1))
                    (t pattern))))
    (unless (string-empty-p raw)
      (gptel-tool-policy--expand-pattern raw))))

(defun gptel-tool-policy--target-buffer (buffer)
  "Return a live buffer for BUFFER, else the current buffer.
BUFFER may be a buffer object or a buffer name: gptel's hook plist is
documented as carrying :buffer, but not which of the two, and guessing wrong
silently reads buffer-local rules from the wrong buffer.  The hook's :buffer
can also be nil or already killed -- an async tool call whose chat buffer went
away -- and neither may abort a policy decision."
  (cond ((buffer-live-p buffer) buffer)
        ((and (stringp buffer) (get-buffer buffer)))
        (t (current-buffer))))

(defun gptel-tool-policy--layered-rules (&optional buffer)
  "Return the effective rules as an alist of (SOURCE . RULE) for BUFFER.
Order is evaluation order: buffer-local session rules, then global session
rules, then `gptel-tool-policy-rules'."
  (with-current-buffer (gptel-tool-policy--target-buffer buffer)
    (append
     (mapcar (lambda (rule) (cons 'buffer rule)) gptel-tool-policy-buffer-rules)
     (mapcar (lambda (rule) (cons 'global rule)) gptel-tool-policy-global-rules)
     (mapcar (lambda (rule) (cons 'default rule)) gptel-tool-policy-rules))))

(defun gptel-tool-policy--effective-rules (&optional buffer)
  "Return the effective rule list for BUFFER, in evaluation order."
  (mapcar #'cdr (gptel-tool-policy--layered-rules buffer)))


;;;; Policy engine

(defconst gptel-tool-policy--action-rank '((allow . 0) (ask . 1) (deny . 2))
  "Restrictiveness ranking of actions; a higher rank wins an aggregation.")

(defun gptel-tool-policy--rank (action)
  "Return the restrictiveness rank of ACTION."
  (or (cdr (assq action gptel-tool-policy--action-rank)) 1))

(defun gptel-tool-policy--decide-path (path class rules)
  "Decide CLASS access to PATH under RULES, first-match-wins.

Return a plist (:action ACTION :rule RULE :path CHECKED).  RULE is nil when
no rule matched and `gptel-tool-policy-default-action' applied.

The truename of PATH, the file actually reached, is decided normally.  PATH
as written, when it differs, counts only through a rule that matches it,
and only when that rule is more restrictive: it catches a deny written in
terms of a symlink, but having no rule of its own it does not fall back to
the default action, which would override an allow matching the truename."
  (let* ((candidates (gptel-tool-policy--path-candidates path))
         (real (car (last candidates)))
         (decision nil))
    (dolist (candidate candidates)
      (let ((rule (seq-find (lambda (r)
                              (gptel-tool-policy--rule-matches-p r class candidate))
                            rules)))
        (when (or rule (eq candidate real))
          (let* ((action (if rule
                             (gptel-tool-policy--rule-action rule)
                           (gptel-tool-policy--sym gptel-tool-policy-default-action)))
                 (this (list :action action :rule rule :path candidate)))
            (when (or (null decision)
                      (> (gptel-tool-policy--rank action)
                         (gptel-tool-policy--rank (plist-get decision :action))))
              (setq decision this))))))
    (or decision
        (list :action (gptel-tool-policy--sym gptel-tool-policy-default-action)
              :rule nil :path path))))

(defun gptel-tool-policy--decide-tree (dir class rules)
  "Decide CLASS access to the directory DIR and everything below it.
Grep and Glob read a whole tree, and a diff applied by Edit can write any
file of its directory, so the decision for DIR alone is not enough: a rule
anchored inside DIR protects something the call reaches.  The anchor of
each such rule is decided like any path, and the most restrictive outcome
wins."
  (let ((decision (gptel-tool-policy--decide-path dir class rules)))
    (dolist (candidate (gptel-tool-policy--path-candidates dir) decision)
      (let ((root (file-name-as-directory candidate)))
        (dolist (rule rules)
          (when (and (gptel-tool-policy--rule-valid-p rule)
                     (eq (gptel-tool-policy--rule-class rule) class))
            (let ((anchor (gptel-tool-policy--rule-anchor rule)))
              (when (and anchor (string-prefix-p root anchor t))
                (let ((nested (gptel-tool-policy--decide-path anchor class rules)))
                  (when (> (gptel-tool-policy--rank (plist-get nested :action))
                           (gptel-tool-policy--rank (plist-get decision :action)))
                    (setq decision nested)))))))))))

(defun gptel-tool-policy--deny-message (decision)
  "Return the message sent to the LLM for a denying DECISION."
  (cond
   ((stringp gptel-tool-policy-deny-message) gptel-tool-policy-deny-message)
   ((eq gptel-tool-policy-deny-message 'detailed)
    (let* ((path (plist-get decision :path))
           (rule (plist-get decision :rule))
           (comment (and rule (gptel-tool-policy--rule-comment rule))))
      (concat "This tool call was blocked by the local security policy: access to "
              (or path "the requested path")
              " is not permitted"
              (cond (comment (format " (%s)." comment))
                    (rule (format " (rule: %s %s %s)."
                                  (gptel-tool-policy--rule-action rule)
                                  (gptel-tool-policy--rule-class rule)
                                  (gptel-tool-policy--rule-pattern rule)))
                    (t (format " (no rule matched; default action is %s)."
                               gptel-tool-policy-default-action))))))
   (t gptel-tool-policy-generic-deny-message)))

(defun gptel-tool-policy--evaluate (name args &optional buffer)
  "Evaluate the policy for tool NAME called with ARGS from BUFFER.
Return `(:block MESSAGE)', `(:confirm t)' or `(:confirm nil)'.  The last
is returned only when every checked path is allowed; it is explicit because
nil would leave gptel to apply its own confirmation settings, and
gptel-agent's write tools ask by themselves.  A local directory, or any
path ending in a slash, is checked as a tree, see
`gptel-tool-policy--decide-tree'.

Paths are expanded, and rules looked up, inside BUFFER when it is live, so a
relative path -- Glob's default \".\", a relative Edit path -- resolves
against the tool call's own `default-directory' rather than whatever buffer
happens to be current when the hook runs."
  (with-current-buffer (gptel-tool-policy--target-buffer buffer)
    (let ((entry (gptel-tool-policy--registry-entry name)))
      (if (null entry)
          (progn
            (display-warning
             'gptel-tool-policy
             (format "Tool %s is not registered with the tool policy manager; asking for confirmation."
                     (or name "<unnamed>"))
             :warning)
            (list :confirm t))
        (let* ((class (gptel-tool-policy--sym (plist-get entry :class)))
               (extractor (plist-get entry :extractor))
               (paths (condition-case err
                          (funcall extractor args)
                        (error
                         (display-warning
                          'gptel-tool-policy
                          (format "Path extraction for tool %s failed (%s); asking for confirmation."
                                  name (error-message-string err))
                          :warning)
                         'extract-error))))
          (cond
           ((eq paths 'extract-error) (list :confirm t))
           (t
            (let* ((rules (gptel-tool-policy--effective-rules (current-buffer)))
                   (paths (seq-filter (lambda (p)
                                        (and (stringp p) (not (string-empty-p p))))
                                      (if (listp paths) paths (list paths))))
                   (decisions
                    (if (null paths)
                        ;; Registered tool with no path argument: nothing was
                        ;; explicitly allowed, so fall back to the default.
                        (list (list :action (gptel-tool-policy--sym
                                             gptel-tool-policy-default-action)
                                    :rule nil :path nil))
                      (mapcar (lambda (p)
                                (if (and (not (file-remote-p (expand-file-name p)))
                                         (or (directory-name-p p)
                                             (file-directory-p p)))
                                    (gptel-tool-policy--decide-tree p class rules)
                                  (gptel-tool-policy--decide-path p class rules)))
                              paths)))
                   (denied (seq-find (lambda (d) (eq (plist-get d :action) 'deny))
                                     decisions))
                   ;; Anything but an explicit `allow' asks, so a malformed
                   ;; default action fails closed.
                   (asked (seq-find (lambda (d) (not (eq (plist-get d :action) 'allow)))
                                    decisions)))
              (cond
               (denied (list :block (gptel-tool-policy--deny-message denied)))
               (asked (list :confirm t))
               (t (list :confirm nil)))))))))))


;;;; Hook function -- the only integration point with gptel

(defun gptel-tool-policy--hook (tool-call &rest _)
  "Enforce the tool policy for TOOL-CALL.
TOOL-CALL is the plist (:name :args :buffer :backend :model) supplied by
`gptel-pre-tool-call-functions'.  Returns `(:block MESSAGE)', `(:confirm t)'
or `(:confirm nil)'.  Any internal error fails safe to `(:confirm t)'.

nil is returned, immediately, when the tool is exempt under
`gptel-tool-policy--bypassed-p' -- the earliest possible exit, taken before
path extraction, the registry lookup and every rule.  See
`gptel-tool-policy-bypass-tools'.

TOOL-CALL is treated as read-only: the policy never rewrites :args, so it can
neither redirect a call nor be used as a path-rewriting sandbox -- that is out
of scope by design."
  (condition-case err
      ;; The body of a `condition-case' is a single form, so the bypass test
      ;; lives inside this `let' rather than sitting before it.  With the
      ;; `proper-list-p' guards in place the test cannot signal, which makes
      ;; the wrapping belt and braces here rather than load-bearing.
      (let ((name (plist-get tool-call :name)))
        (if (gptel-tool-policy--bypassed-p name)
            nil
          (gptel-tool-policy--evaluate name
                                       (plist-get tool-call :args)
                                       (plist-get tool-call :buffer))))
    (error
     (display-warning
      'gptel-tool-policy
      (format "Policy evaluation failed (%s); asking for confirmation."
              (error-message-string err))
      :warning)
     (list :confirm t))))

;;;###autoload
(define-minor-mode gptel-tool-policy-mode
  "Enforce path-based policy on every gptel tool call.

When enabled, `gptel-tool-policy--hook' is added to
`gptel-pre-tool-call-functions' at depth 100, after other functions: gptel
runs the arguments as other functions may have rewritten them, so those are
the ones to check, and the policy's :confirm has the last word.  That
includes the `(:confirm nil)' of an allowed call, which cancels a
confirmation an earlier function asked for: the policy cannot see what
earlier functions returned."
  :global t
  :group 'gptel-tool-policy
  :lighter " ToolPolicy"
  (if gptel-tool-policy-mode
      (add-hook 'gptel-pre-tool-call-functions #'gptel-tool-policy--hook 100)
    (remove-hook 'gptel-pre-tool-call-functions #'gptel-tool-policy--hook)))


;;;; Interactive commands (session-only, never touch the defcustom)

(defun gptel-tool-policy--read-action ()
  "Prompt for a rule action."
  (intern (completing-read "Action: " '("allow" "deny" "ask") nil t nil nil "deny")))

(defun gptel-tool-policy--classes ()
  "Return the operation classes known to the registry, as strings."
  (let ((classes (delete-dups
                  (mapcar (lambda (cell)
                            (symbol-name
                             (gptel-tool-policy--sym (plist-get (cdr cell) :class))))
                          gptel-tool-policy-tool-registry))))
    (or (sort classes #'string<) '("read" "write"))))

(defun gptel-tool-policy--read-class ()
  "Prompt for an operation class."
  (intern (completing-read "Operation class: " (gptel-tool-policy--classes)
                           nil t nil nil "read")))

(defun gptel-tool-policy--read-scope ()
  "Prompt for a rule scope, defaulting to buffer."
  (intern (completing-read "Scope: " '("buffer" "global") nil t nil nil "buffer")))

(defun gptel-tool-policy--resolve (path)
  "Return PATH expanded, with symlinks resolved when PATH is local."
  (let ((path (expand-file-name path)))
    (if (file-remote-p path) path (gptel-tool-policy--truename path))))

(defun gptel-tool-policy--pattern-for-file (path)
  "Return a rule pattern for PATH: recursive for a directory, exact otherwise.
A trailing slash counts as \"directory\" on its own, so a directory that does
not exist yet -- `read-file-name' is called with MUSTMATCH nil -- still yields
a recursive \"/**\" pattern instead of an exact-match rule on its name.
Symlinks are resolved: the policy decides on real locations, see
`gptel-tool-policy--decide-path'."
  (let* ((trailing (directory-name-p path))
         (path (gptel-tool-policy--resolve path)))
    (if (or trailing (file-directory-p path))
        (concat (directory-file-name path) "/**")
      (directory-file-name path))))

(defun gptel-tool-policy--timestamp-comment (label)
  "Return a comment string combining LABEL and the current time."
  (format "%s at %s" label (format-time-string "%Y-%m-%d %H:%M:%S")))

(defun gptel-tool-policy--prepend-rule (rule scope &optional buffer)
  "Prepend RULE to the session list selected by SCOPE.
SCOPE is `buffer' (in BUFFER, default the current buffer) or `global'."
  (unless (gptel-tool-policy--rule-valid-p rule)
    (user-error "Malformed rule: %S" rule))
  (if (eq scope 'global)
      (setq gptel-tool-policy-global-rules
            (cons rule gptel-tool-policy-global-rules))
    (with-current-buffer (if (buffer-live-p buffer) buffer (current-buffer))
      (setq-local gptel-tool-policy-buffer-rules
                  (cons rule gptel-tool-policy-buffer-rules))))
  (message "%s rule added (%s scope): %s %s %s"
           (capitalize (symbol-name (gptel-tool-policy--rule-action rule)))
           scope
           (gptel-tool-policy--rule-action rule)
           (gptel-tool-policy--rule-class rule)
           (gptel-tool-policy--rule-pattern rule))
  rule)

;;;###autoload
(defun gptel-tool-policy-add-rule (action class scope pattern &optional comment)
  "Add an ACTION rule for CLASS matching PATTERN, in SCOPE, described by COMMENT.
ACTION is `allow', `deny' or `ask'; CLASS is an operation class such as
`read' or `write'; SCOPE is `buffer' or `global'; PATTERN accepts the
\"DIR/**\", \"PREFIX*\" and exact forms.  COMMENT is the text shown by
`gptel-tool-policy-show-rules' and by the `detailed' deny message; when it is
empty or omitted a timestamp is used instead.  The rule is prepended to its
layer and lasts for this session only."
  (interactive
   (let* ((action (gptel-tool-policy--read-action))
          (class (gptel-tool-policy--read-class))
          (scope (gptel-tool-policy--read-scope))
          (pattern (read-string
                    (format "Path pattern for %s %s (%s scope): "
                            action class scope)))
          (comment (read-string "Comment (optional): ")))
     (list action class scope pattern comment)))
  (let ((pattern (string-trim (or pattern "")))
        (comment (string-trim (or comment ""))))
    (when (string-empty-p pattern)
      (user-error "Empty path pattern"))
    (gptel-tool-policy--prepend-rule
     (list action class pattern
           (if (string-empty-p comment)
               (gptel-tool-policy--timestamp-comment "Added interactively")
             comment))
     scope)))

;;;###autoload
(defun gptel-tool-policy-whitelist-cwd (class scope)
  "Allow CLASS access to the current directory and everything below it.
SCOPE is `buffer' or `global'; the rule lasts for this session only."
  (interactive
   (list (gptel-tool-policy--read-class) (gptel-tool-policy--read-scope)))
  (let ((pattern (concat (directory-file-name
                          (file-local-name
                           (gptel-tool-policy--resolve default-directory)))
                         "/**")))
    (gptel-tool-policy--prepend-rule
     (list 'allow class pattern
           (gptel-tool-policy--timestamp-comment "Whitelisted"))
     scope)))

;;;###autoload
(defun gptel-tool-policy-whitelist-path (class scope path)
  "Allow CLASS access to PATH, in SCOPE.
A directory becomes a recursive \"/**\" rule, a file an exact rule.  PATH
need not exist yet.  The rule lasts for this session only."
  (interactive
   (let* ((class (gptel-tool-policy--read-class))
          (scope (gptel-tool-policy--read-scope))
          (path (read-file-name
                 (format "Whitelist path for %s (%s scope): " class scope)
                 nil nil nil)))
     (list class scope path)))
  (when (or (null path) (string-empty-p (string-trim path)))
    (user-error "Empty path"))
  (gptel-tool-policy--prepend-rule
   (list 'allow class (gptel-tool-policy--pattern-for-file path)
         (gptel-tool-policy--timestamp-comment "Whitelisted"))
   scope))

(defun gptel-tool-policy--rule-label (source rule &optional index)
  "Return a human readable label for RULE from SOURCE, optionally numbered."
  (format "%s[%s] %-5s %-6s %s%s"
          (if index (format "%2d. " index) "")
          source
          (or (gptel-tool-policy--rule-action rule) "?")
          (or (gptel-tool-policy--rule-class rule) "?")
          (or (gptel-tool-policy--rule-pattern rule) "?")
          (let ((comment (gptel-tool-policy--rule-comment rule)))
            (if comment (format "  ;; %s" comment) ""))))

(defun gptel-tool-policy--interactive-rules ()
  "Return an alist of (SOURCE . RULE) for the session-only layers.
Derived from `gptel-tool-policy--layered-rules' so that the two views cannot
drift apart; only the persistent defcustom layer is filtered out."
  (seq-remove (lambda (entry) (eq (car entry) 'default))
              (gptel-tool-policy--layered-rules)))

(defun gptel-tool-policy--remove-first (rule rules)
  "Return RULES without its first element `equal' to RULE."
  (let ((seen nil) (result '()))
    (dolist (candidate rules)
      (if (and (not seen) (equal candidate rule))
          (setq seen t)
        (push candidate result)))
    (nreverse result)))

;;;###autoload
(defun gptel-tool-policy-remove-rule ()
  "Remove a single session rule, buffer-local or global.
Rules from `gptel-tool-policy-rules' are never touched."
  (interactive)
  (let ((entries (gptel-tool-policy--interactive-rules)))
    (if (null entries)
        (message "No session rules to remove (the defcustom is not affected)")
      (let* ((table (let ((index 0) (alist '()))
                      (dolist (entry entries)
                        (setq index (1+ index))
                        (push (cons (gptel-tool-policy--rule-label
                                     (car entry) (cdr entry) index)
                                    entry)
                              alist))
                      (nreverse alist)))
             (choice (completing-read "Remove session rule: "
                                      (mapcar #'car table) nil t))
             (entry (cdr (assoc choice table)))
             (source (car entry))
             (rule (cdr entry)))
        (unless entry
          (user-error "No rule selected"))
        (if (eq source 'global)
            (setq gptel-tool-policy-global-rules
                  (gptel-tool-policy--remove-first rule gptel-tool-policy-global-rules))
          (setq-local gptel-tool-policy-buffer-rules
                      (gptel-tool-policy--remove-first
                       rule gptel-tool-policy-buffer-rules)))
        (message "Removed %s rule: %s %s %s"
                 source
                 (gptel-tool-policy--rule-action rule)
                 (gptel-tool-policy--rule-class rule)
                 (gptel-tool-policy--rule-pattern rule))))))

;;;###autoload
(defun gptel-tool-policy-clear-rules (scope)
  "Clear all session rules in SCOPE, `buffer' or `global'.
`gptel-tool-policy-rules' is never touched."
  (interactive (list (gptel-tool-policy--read-scope)))
  (if (eq scope 'global)
      (let ((count (length gptel-tool-policy-global-rules)))
        (setq gptel-tool-policy-global-rules nil)
        (message "Cleared %d global session rule%s"
                 count (if (= count 1) "" "s")))
    (let ((count (length gptel-tool-policy-buffer-rules)))
      (kill-local-variable 'gptel-tool-policy-buffer-rules)
      (setq-local gptel-tool-policy-buffer-rules nil)
      (message "Cleared %d buffer-local session rule%s in %s"
               count (if (= count 1) "" "s") (buffer-name)))))

(defun gptel-tool-policy--alist-string-keys (alist)
  "Return the string keys of ALIST, in order.
Any shape is tolerated: a non-list, an improper list, entries that are not
conses and entries whose key is not a string are skipped rather than
signalling.  One of the alists this walks is private to gptel, so it has to
survive an upstream restructure without breaking the command that uses it."
  (let ((tail alist) (keys '()))
    (while (consp tail)
      (let ((cell (car tail)))
        (when (and (consp cell) (stringp (car cell)))
          (push (car cell) keys)))
      (setq tail (cdr tail)))
    (nreverse keys)))

(defun gptel-tool-policy--known-tool-names (&optional with-source)
  "Return tool names for `gptel-tool-policy-add-bypass', sorted and deduped.

Three sources are tried in order; the first that yields anything wins:

  1. `gptel--known-tools' -- every tool registered with gptel, enabled or
     not.  This is the list the bypass command wants, since it lets you
     name a tool you have not enabled yet, but the variable is internal to
     gptel, which is why the two fallbacks below exist.
  2. `gptel-tools' -- the enabled tools only, read through the public
     accessor `gptel-tool-name'.
  3. `gptel-tool-policy-tool-registry' -- the tools this policy covers.

Falling back on an empty level 1 as well as an unbound one matters: gptel can
be loaded with no tools registered yet, and completion with `require-match'
against an empty table would make the command impossible to complete.

With WITH-SOURCE non-nil, return a cons cell of SOURCE and NAMES instead of
NAMES alone, where SOURCE is `known-tools', `enabled' or `registry'; the
command uses it to say that the offered list is narrower than intended.
Never signals, whatever shape those sources are in."
  (let* ((source 'known-tools)
         (names
          (and (boundp 'gptel--known-tools)
               (let ((tail gptel--known-tools) (acc '()))
                 (while (consp tail)
                   (let ((category (car tail)))
                     (when (consp category)
                       (setq acc
                             (nconc acc (gptel-tool-policy--alist-string-keys
                                         (cdr category))))))
                   (setq tail (cdr tail)))
                 acc))))
    (unless names
      (setq source 'enabled
            names (and (boundp 'gptel-tools)
                       (fboundp 'gptel-tool-name)
                       (let ((tail gptel-tools) (acc '()))
                         (while (consp tail)
                           (let ((name (ignore-errors
                                         (gptel-tool-name (car tail)))))
                             (when (stringp name) (push name acc)))
                           (setq tail (cdr tail)))
                         (nreverse acc)))))
    (unless names
      (setq source 'registry
            names (gptel-tool-policy--alist-string-keys
                   gptel-tool-policy-tool-registry)))
    (setq names (sort (delete-dups names) #'string<))
    (if with-source (cons source names) names)))

;;;###autoload
(defun gptel-tool-policy-add-bypass (name)
  "Exempt the tool called NAME from the policy for this session.

NAME is prepended to `gptel-tool-policy-global-bypass-tools', after which
every call to that tool skips path extraction, the registry and every rule;
gptel's own confirmation settings still apply.  Read the docstring of
`gptel-tool-policy-bypass-tools' first: this is unconditional trust, and it
overrides the deny rules shipped for ~/.ssh, ~/.gnupg and friends.

Interactively, NAME is completed from the tools gptel knows about, enabled or
not, and must be one of them.  The prompt says so when that list had to fall
back to a narrower source; see `gptel-tool-policy--known-tool-names'.

Nothing is added when NAME is already covered by either layer -- the layer
covering it is reported instead -- so running this twice is a no-op.  The
defcustom is never modified.  Returns the session bypass list."
  (interactive
   (let* ((table (gptel-tool-policy--known-tool-names t))
          (names (cdr table))
          (prompt (cond
                   ((eq (car table) 'enabled)
                    "Bypass tool (list degraded to gptel's enabled tools): ")
                   ((eq (car table) 'registry)
                    "Bypass tool (list degraded to the policy registry): ")
                   (t "Bypass tool: "))))
     (unless names
       (user-error "No tool names to complete against; is gptel loaded?"))
     (list (completing-read prompt names nil t))))
  (unless (stringp name)
    (user-error "Tool name must be a string: %S" name))
  (let ((name (string-trim name)))
    (when (string-empty-p name)
      (user-error "Empty tool name"))
    ;; Consing onto a malformed list would produce a longer malformed list,
    ;; which grants no bypass at all: say so instead of pretending to work.
    (unless (proper-list-p gptel-tool-policy-global-bypass-tools)
      (user-error "%s is not a proper list (%S); reset it with setq first"
                  'gptel-tool-policy-global-bypass-tools
                  gptel-tool-policy-global-bypass-tools))
    (let ((covered
           (cond ((member name gptel-tool-policy-global-bypass-tools) 'global)
                 ((and (proper-list-p gptel-tool-policy-bypass-tools)
                       (member name gptel-tool-policy-bypass-tools))
                  'default))))
      (if covered
          (message "%s already bypasses the policy (%s layer); nothing added"
                   name covered)
        (setq gptel-tool-policy-global-bypass-tools
              (cons name gptel-tool-policy-global-bypass-tools))
        (message "%s now bypasses the policy entirely (global session layer)"
                 name))
      gptel-tool-policy-global-bypass-tools)))

(defun gptel-tool-policy--bypass-description ()
  "Return the \"Bypass tools\" field of `gptel-tool-policy-show-rules'.
Layers are labeled with the `global' and `default' vocabulary the rule
listing already uses, an empty layer is omitted, and the whole field reads
\"none\" when both are empty.  A layer whose value is not a proper list is
reported as ignored rather than dropped silently: it grants no bypass at all
\(see `gptel-tool-policy--bypassed-p'), which is worth seeing here."
  (let* ((layers (list (cons "global" gptel-tool-policy-global-bypass-tools)
                       (cons "default" gptel-tool-policy-bypass-tools)))
         (parts (delq nil
                      (mapcar
                       (lambda (layer)
                         (let ((label (car layer))
                               (value (cdr layer)))
                           (cond
                            ((not (proper-list-p value))
                             (format "%s: <malformed, ignored>" label))
                            ((null value) nil)
                            (t (format "%s: %s" label
                                       (mapconcat (lambda (entry)
                                                    (format "%s" entry))
                                                  value ", "))))))
                       layers))))
    (if parts (mapconcat #'identity parts "; ") "none")))

;;;###autoload
(defun gptel-tool-policy-show-rules ()
  "Display the effective rule set in evaluation order, labeled by source."
  (interactive)
  (let* ((origin (current-buffer))
         (entries (gptel-tool-policy--layered-rules origin))
         (buffer (get-buffer-create "*gptel tool policy*")))
    (with-current-buffer buffer
      (let ((inhibit-read-only t))
        (erase-buffer)
        (insert (format "gptel tool policy — effective rules for buffer %s\n"
                        (buffer-name origin)))
        (insert (make-string 70 ?=) "\n\n")
        (insert (format "Policy active         : %s\n"
                        (if (and (boundp 'gptel-pre-tool-call-functions)
                                 (memq #'gptel-tool-policy--hook
                                       gptel-pre-tool-call-functions))
                            "yes" "no (enable gptel-tool-policy-mode)"))
                (format "Default action        : %s\n" gptel-tool-policy-default-action)
                (format "Deny message          : %s\n" gptel-tool-policy-deny-message)
                (format "Registered tools      : %s\n"
                        (mapconcat (lambda (cell)
                                     (format "%s(%s)" (car cell)
                                             (gptel-tool-policy--sym
                                              (plist-get (cdr cell) :class))))
                                   gptel-tool-policy-tool-registry ", "))
                (format "Bypass tools          : %s\n"
                        (gptel-tool-policy--bypass-description))
                (format "Rules in effect       : %d buffer, %d global, %d default\n\n"
                        (seq-count (lambda (e) (eq (car e) 'buffer)) entries)
                        (seq-count (lambda (e) (eq (car e) 'global)) entries)
                        (seq-count (lambda (e) (eq (car e) 'default)) entries)))
        (insert "Evaluation order (first match wins):\n")
        (insert "  buffer  = buffer-local session rules\n"
                "  global  = global session rules\n"
                "  default = gptel-tool-policy-rules (defcustom, persistent)\n\n")
        (if (null entries)
            (insert "No rules defined; every call falls back to the default action.\n")
          (let ((index 0))
            (dolist (entry entries)
              (setq index (1+ index))
              (insert (gptel-tool-policy--rule-label (car entry) (cdr entry) index)
                      (if (gptel-tool-policy--rule-valid-p (cdr entry))
                          ""
                        "   <-- MALFORMED, ignored")
                      "\n"))))
        (insert "\nSession rules are not persisted; only the defcustom survives a restart.\n")
        (goto-char (point-min))
        (special-mode)))
    (display-buffer buffer)
    buffer))

(provide 'gptel-tool-policy)

;; Report a bypass list that is not a proper list.  Such a value grants no
;; bypass -- see `gptel-tool-policy--bypassed-p' -- so this is unconditional:
;; a configuration that is being discarded is worth knowing about whether or
;; not the policy is armed at load.
(gptel-tool-policy--validate-bypass-lists)

;; Arm the policy as soon as this file is loaded: a security layer you forgot
;; to switch on protects nothing.  Set `gptel-tool-policy-enable-on-load' to
;; nil before loading to opt out.
(when gptel-tool-policy-enable-on-load
  (gptel-tool-policy-mode 1))

;;; gptel-tool-policy.el ends here
