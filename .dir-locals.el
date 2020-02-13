(
 (rust-mode . ((indent-tabs-mode . nil)
               (show-trailing-whitespace . t)
               (c-basic-offset . 4)
               (tab-width . 4)
               ))

 (nil . ((counsel-etags-update-tags-backend . (lambda (src-dir) (shell-command "rusty-tags emacs")))
         ; (counsel-etags-extra-tags-files . ("~/third-party-lib/rusty-tags.emacs" "$RUST_SRC_PATH/rusty-tags.emacs"))
         (counsel-etags-tags-file-name . "rusty-tags.emacs"))))

