package internal

import "fmt"

// Completion prints a shell completion script for the given shell.
func Completion(shell string) (string, error) {
	switch shell {
	case "bash":
		return `_envdiff() {
  local cur prev
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=($(compgen -W "scan diff check probe version completion" -- "$cur"))
    return 0
  fi
  case "$prev" in
    --out|--config|--baseline) COMPREPLY=($(compgen -f -- "$cur")); return 0 ;;
    --target) COMPREPLY=($(compgen -W "local net:// ssh:// file://" -- "$cur")); return 0 ;;
    probe) COMPREPLY=($(compgen -W "dns tls port http" -- "$cur")); return 0 ;;
    completion) COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur")); return 0 ;;
  esac
  COMPREPLY=($(compgen -W "--target --out --root --config --baseline --json" -- "$cur"))
}
complete -F _envdiff envdiff
`, nil
	case "zsh":
		return `#compdef envdiff
_envdiff() {
  local -a cmds=(scan diff check probe version completion)
  if (( CURRENT == 2 )); then
    _describe 'command' cmds
    return
  fi
  _arguments \
    '--target[target spec]:target:(local net:// ssh:// file://)' \
    '--out[snapshot output]:file:_files' \
    '--root[repo root]:dir:_files -/' \
    '--config[manifest]:file:_files' \
    '--baseline[baseline snapshot]:file:_files' \
    '--json[structured output]'
}
_envdiff "$@"
`, nil
	case "fish":
		return `complete -c envdiff -n '__fish_use_subcommand' -a 'scan diff check probe version completion'
complete -c envdiff -l target -a 'local net:// ssh:// file://' -d 'scan target'
complete -c envdiff -l out -r -F -d 'snapshot output'
complete -c envdiff -l root -r -F -d 'repo root'
complete -c envdiff -l config -r -F -d 'manifest file'
complete -c envdiff -l baseline -r -F -d 'baseline snapshot'
complete -c envdiff -l json -d 'structured output'
`, nil
	}
	return "", fmt.Errorf("unknown shell %q — use bash, zsh, or fish", shell)
}
