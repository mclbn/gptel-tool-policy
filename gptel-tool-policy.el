;;; gptel-tool-policy.el --- Path-based security policy for gptel tool calls -*- lexical-binding: t; -*-

;; A path-based security policy layer for filesystem tools invoked through
;; gptel.  It installs a single function on `gptel-pre-tool-call-functions'
;; and enforces ordered allow / deny / ask rules against normalized paths.
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
;;   M-x gptel-tool-policy-show-rules      show the effective rule set
;;
;; Rule format: (ACTION CLASS PATTERN COMMENT)
;;
;;   (deny  read  "~/.ssh/**"     "Never expose SSH keys")
;;   (allow write "~/projects/**" "Write project files")
;;   (ask   read  "~/**"          "Ask elsewhere in $HOME")
;;
;; Patterns: "DIR/**" recursive match, "PREFIX*" prefix match, otherwise
;; exact match.  Rules are evaluated in order; the first match wins, so
;; place denies for dangerous paths before broader allows.
;;
;; Components:
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
;;     every path is explicitly allowed does the hook return nil.
;;
;;     Paths are expanded in the tool call's own buffer, so a relative path
;;     (Glob's default ".", diff targets) resolves against that buffer's
;;     `default-directory' rather than whatever buffer happens to be current
;;     when the hook runs.
;;
;;   * Interactive commands -- `gptel-tool-policy-add-rule',
;;     `gptel-tool-policy-whitelist-cwd', `gptel-tool-policy-whitelist-path',
;;     `gptel-tool-policy-remove-rule', `gptel-tool-policy-clear-rules' and
;;     `gptel-tool-policy-show-rules'.  All additions are session-only and
;;     are prepended to the front of their layer; the defcustom is never
;;     modified.  `gptel-tool-policy-whitelist-path' treats a trailing "/"
;;     as a directory, so a not-yet-created directory still gets "/**".
;;     `gptel-tool-policy-show-rules' reports a per-layer rule count.
;;
;; Design constraints (by design):
;;
;;   * The Bash tool is not covered.  MCP filesystem tools are out of scope.
;;     Tramp matching applies to the local part of a remote path only (with
;;     a warning).
;;
;;   * Defcustoms intentionally omit `:safe' predicates.  A `:safe'
;;     predicate would let any project's .dir-locals.el silently replace the
;;     policy, handing the kill switch to the material the policy exists to
;;     guard against.  Rules must come from your own init file or a session
;;     command.

;;; Code:

(require 'seq)
(require 'subr-x)

(defvar gptel-pre-tool-call-functions)


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
        before matching.
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

(defun gptel-tool-policy--arg-present-p (args key)
  "Return non-nil when KEY appears in ARGS at all, whatever its value.
Distinguishes \"the tool did not send this key\" from \"the tool sent it as
false\", which `gptel-tool-policy--arg' alone cannot do."
  (let ((want (gptel-tool-policy--key-name key)))
    (cond
     ((not (consp args)) nil)
     ((consp (car args))
      (and (seq-find (lambda (cell)
                       (and (consp cell)
                            (equal want (gptel-tool-policy--key-name (car cell)))))
                     args)
           t))
     (t
      (let ((tail args) (found nil))
        (while (and tail (not found))
          (when (equal want (gptel-tool-policy--key-name (car tail)))
            (setq found t))
          (setq tail (cdr (cdr tail))))
        found)))))

(defun gptel-tool-policy--string-arg (args key)
  "Return the value of KEY in ARGS when it is a non-empty string."
  (let ((value (gptel-tool-policy--arg args key)))
    (and (stringp value)
         (not (string-empty-p (string-trim value)))
         (string-trim value))))


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
  "Extract paths checked for a Grep call from ARGS (:path)."
  (gptel-tool-policy--extract-key args :path))

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

(defun gptel-tool-policy--diff-target-paths (diff base-dir)
  "Return the target paths named by \"+++\" headers in DIFF.
Each header path has an optional \"a/\" or \"b/\" prefix stripped and is
resolved against BASE-DIR.  \"/dev/null\" targets are ignored."
  (let ((paths '()))
    (with-temp-buffer
      (insert (or diff ""))
      (goto-char (point-min))
      (while (re-search-forward "^\\+\\+\\+[ \t]+\\([^\t\n]+\\)" nil t)
        (let* ((raw (string-trim (match-string 1)))
               ;; Strip every leading "a/" or "b/", not just one: "b//x"
               ;; must not become the absolute path "/x".
               (stripped (replace-regexp-in-string "\\`[ab]/+" "" raw))
               (rebased (if (and (not (string= raw stripped))
                                 (file-name-absolute-p stripped))
                            (concat "./" (string-remove-prefix "/" stripped))
                          stripped)))
          (unless (or (string-empty-p stripped) (string= stripped "/dev/null"))
            (push (expand-file-name stripped base-dir) paths)
            ;; A stripped header that came out absolute is ambiguous: patch may
            ;; read it either way, so check both.  Extra candidates can only
            ;; make the verdict stricter.
            (unless (string= rebased stripped)
              (push (expand-file-name rebased base-dir) paths))))))
    (nreverse paths)))

(defun gptel-tool-policy--extract-edit (args)
  "Extract paths checked for an Edit call from ARGS.

:path is ALWAYS checked, whatever the mode: it is the file the tool nominally
targets, and dropping it would let content decide what gets inspected.

Diff mode is taken from the :diff argument when that key is present, and
inferred from the presence of \"+++\" headers when it is not, so the extractor
is correct whether or not the tool source declares the mode.  In diff mode the
\"+++\" headers of :new_str name the files actually touched; each is resolved
against the directory of :path and added to the list, so a header such as
\"+++ b/../../.ssh/config\" cannot escape the policy."
  (let* ((path (gptel-tool-policy--string-arg args :path))
         (new-str (gptel-tool-policy--arg args :new_str))
         (diff-flag (gptel-tool-policy--arg args :diff))
         (diff-mode (if (gptel-tool-policy--arg-present-p args :diff)
                        (and diff-flag (not (eq diff-flag :json-false)))
                      t))
         (base (and path (or (file-name-directory (expand-file-name path))
                             default-directory)))
         (diff-paths (and diff-mode (stringp new-str) base
                          (gptel-tool-policy--diff-target-paths new-str base))))
    (delete-dups (append (and path (list path)) diff-paths))))


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
Both the expanded path and its truename are returned (deduplicated), so
that a symlink pointing from an allowed directory into a denied one is
still caught, while rules written in terms of a symlinked directory keep
working.  A remote path warns and is reduced to its local part, unresolved."
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

(defun gptel-tool-policy--match-pattern (pattern path)
  "Return non-nil when PATTERN matches the normalized PATH.
\"DIR/**\" is checked first (recursive match of DIR and everything under
it), then \"PREFIX*\" (prefix match), then an exact path match."
  (when (and (stringp pattern) (stringp path) (not (string-empty-p pattern)))
    (cond
     ;; 1. Recursive directory match.
     ((string-suffix-p "/**" pattern)
      (let* ((raw (substring pattern 0 -3))
             (base (directory-file-name
                    (if (string-empty-p raw)
                        "/"
                      (gptel-tool-policy--expand-pattern raw)))))
        (or (string= (directory-file-name path) base)
            (string-prefix-p (file-name-as-directory base) path))))
     ;; 2. Prefix match.
     ((string-suffix-p "*" pattern)
      (let ((prefix (substring pattern 0 -1)))
        (if (string-empty-p prefix)
            t
          (string-prefix-p (gptel-tool-policy--expand-pattern prefix) path))))
     ;; 3. Exact match.
     (t
      (string= (directory-file-name (gptel-tool-policy--expand-pattern pattern))
               (directory-file-name path))))))


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
  "Return non-nil when RULE is well formed."
  (and (consp rule)
       (memq (gptel-tool-policy--rule-action rule) '(allow deny ask))
       (gptel-tool-policy--rule-class rule)
       (stringp (gptel-tool-policy--rule-pattern rule))
       (not (string-empty-p (gptel-tool-policy--rule-pattern rule)))))

(defun gptel-tool-policy--rule-matches-p (rule class path)
  "Return non-nil when RULE covers CLASS and matches PATH."
  (and (gptel-tool-policy--rule-valid-p rule)
       (eq (gptel-tool-policy--rule-class rule) class)
       (gptel-tool-policy--match-pattern (gptel-tool-policy--rule-pattern rule)
                                         path)))

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
no rule matched and `gptel-tool-policy-default-action' applied.  Both the
expanded path and its truename are checked; the more restrictive outcome
wins."
  (let ((decision nil))
    (dolist (candidate (gptel-tool-policy--path-candidates path))
      (let* ((rule (seq-find (lambda (r)
                               (gptel-tool-policy--rule-matches-p r class candidate))
                             rules))
             (action (if rule
                         (gptel-tool-policy--rule-action rule)
                       (gptel-tool-policy--sym gptel-tool-policy-default-action)))
             (this (list :action action :rule rule :path candidate)))
        (when (or (null decision)
                  (> (gptel-tool-policy--rank action)
                     (gptel-tool-policy--rank (plist-get decision :action))))
          (setq decision this))))
    (or decision
        (list :action (gptel-tool-policy--sym gptel-tool-policy-default-action)
              :rule nil :path path))))

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
Return `(:block MESSAGE)', `(:confirm t)' or nil.  nil is returned only when
every checked path was explicitly allowed by a matching rule.

Paths are expanded, and rules looked up, inside BUFFER when it is live, so a
relative path -- Glob's default \".\", a diff target -- resolves against the
tool call's own `default-directory' rather than whatever buffer happens to be
current when the hook runs."
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
                                (gptel-tool-policy--decide-path p class rules))
                              paths)))
                   (denied (seq-find (lambda (d) (eq (plist-get d :action) 'deny))
                                     decisions))
                   (asked (seq-find (lambda (d) (eq (plist-get d :action) 'ask))
                                    decisions)))
              (cond
               (denied (list :block (gptel-tool-policy--deny-message denied)))
               (asked (list :confirm t))
               (t nil))))))))))


;;;; Hook function -- the only integration point with gptel

(defun gptel-tool-policy--hook (tool-call &rest _)
  "Enforce the tool policy for TOOL-CALL.
TOOL-CALL is the plist (:name :args :buffer :backend :model) supplied by
`gptel-pre-tool-call-functions'.  Returns `(:block MESSAGE)', `(:confirm t)'
or nil.  Any internal error fails safe to `(:confirm t)'.

TOOL-CALL is treated as read-only: the policy never rewrites :args, so it can
neither redirect a call nor be used as a path-rewriting sandbox -- that is out
of scope by design."
  (condition-case err
      (gptel-tool-policy--evaluate (plist-get tool-call :name)
                                   (plist-get tool-call :args)
                                   (plist-get tool-call :buffer))
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

When enabled, `gptel-tool-policy--hook' is placed at the front of
`gptel-pre-tool-call-functions' so that it sees unmodified tool arguments."
  :global t
  :group 'gptel-tool-policy
  :lighter " ToolPolicy"
  (if gptel-tool-policy-mode
      (add-hook 'gptel-pre-tool-call-functions #'gptel-tool-policy--hook)
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

(defun gptel-tool-policy--pattern-for-file (path)
  "Return a rule pattern for PATH: recursive for a directory, exact otherwise.
A trailing slash counts as \"directory\" on its own, so a directory that does
not exist yet -- `read-file-name' is called with MUSTMATCH nil -- still yields
a recursive \"/**\" pattern instead of an exact-match rule on its name."
  (let* ((trailing (directory-name-p path))
         (path (expand-file-name path)))
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
                          (file-local-name (expand-file-name default-directory)))
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

;; Arm the policy as soon as this file is loaded: a security layer you forgot
;; to switch on protects nothing.  Set `gptel-tool-policy-enable-on-load' to
;; nil before loading to opt out.
(when gptel-tool-policy-enable-on-load
  (gptel-tool-policy-mode 1))

;;; gptel-tool-policy.el ends here
