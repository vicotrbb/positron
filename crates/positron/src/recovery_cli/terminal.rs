//! Interactive-only, echo-disabled, bounded passphrase entry.
use positron_kernel::RecoveryPassphrase;
use std::io::{IsTerminal, Read, Write};
use zeroize::Zeroizing;
pub(super) fn passphrase(confirm: bool) -> Result<RecoveryPassphrase, &'static str> {
    let mut value = read("Recovery passphrase (at least 12 bytes): ")?;
    if confirm && *value != *read("Confirm recovery passphrase: ")? {
        return Err("passphrases differ");
    }
    RecoveryPassphrase::from_interactive(std::mem::take(&mut *value))
        .map_err(|_| "passphrase must contain 12 to 1024 bytes")
}
fn read(prompt: &str) -> Result<Zeroizing<String>, &'static str> {
    let mut terminal=std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").map_err(|_|"interactive terminal required; passphrases cannot come from argv, environment, configuration or redirected input")?;
    if !terminal.is_terminal() {
        return Err("interactive terminal required");
    }
    let original =
        rustix::termios::tcgetattr(&terminal).map_err(|_| "terminal echo control unavailable")?;
    if !original
        .local_modes
        .contains(rustix::termios::LocalModes::ICANON)
    {
        return Err("canonical interactive terminal required");
    }
    let mut hidden = original.clone();
    hidden.local_modes.remove(
        rustix::termios::LocalModes::ECHO
            | rustix::termios::LocalModes::ECHONL
            | rustix::termios::LocalModes::ISIG,
    );
    // Canonical editing stays in the terminal. Consume cancellation keys as
    // line delimiters so Ctrl-C / Ctrl-Z return through echo restoration.
    hidden.special_codes[rustix::termios::SpecialCodeIndex::VEOL] = 3;
    hidden.special_codes[rustix::termios::SpecialCodeIndex::VEOL2] = 26;
    rustix::termios::tcsetattr(&terminal, rustix::termios::OptionalActions::Now, &hidden)
        .map_err(|_| "terminal echo control unavailable")?;
    let result = (|| {
        terminal
            .write_all(prompt.as_bytes())
            .map_err(|_| "terminal output unavailable")?;
        terminal
            .flush()
            .map_err(|_| "terminal output unavailable")?;
        let mut bytes = Zeroizing::new([0u8; 1025]);
        let length = terminal
            .read(bytes.as_mut())
            .map_err(|_| "terminal input unavailable")?;
        let input = bytes.get(..length).ok_or("terminal input unavailable")?;
        if input.iter().any(|byte| matches!(byte, 3 | 26 | 28)) {
            return Err("passphrase entry cancelled");
        }
        if length == 0 || length > 1024 || input.last() != Some(&b'\n') {
            return Err("passphrase exceeds supported bound");
        }
        let value = std::str::from_utf8(input)
            .map_err(|_| "passphrase must be UTF-8")?
            .trim_end_matches(['\r', '\n']);
        Ok(Zeroizing::new(value.to_owned()))
    })();
    rustix::termios::tcsetattr(&terminal, rustix::termios::OptionalActions::Now, &original)
        .map_err(|_| "terminal echo restoration failed")?;
    terminal
        .write_all(b"\n")
        .map_err(|_| "terminal output unavailable")?;
    result
}
