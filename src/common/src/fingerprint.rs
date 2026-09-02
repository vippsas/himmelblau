/*
 * fprintd integration used by the privileged Himmelblau authentication path.
 *
 * fprintd owns fingerprint templates and performs all matching. This module
 * receives only the D-Bus verification status; biometric data never enters
 * Himmelblau or its daemon IPC protocol.
 */
use tracing::debug;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::OwnedObjectPath;

const FPRINTD_DESTINATION: &str = "net.reactivated.Fprint";
const FPRINTD_MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const FPRINTD_MANAGER_INTERFACE: &str = "net.reactivated.Fprint.Manager";
const FPRINTD_DEVICE_INTERFACE: &str = "net.reactivated.Fprint.Device";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationStatus {
    Matched,
    Continue,
    Failed,
}

fn verification_status(result: &str, done: bool) -> VerificationStatus {
    if result == "verify-match" {
        VerificationStatus::Matched
    } else if result == "verify-no-match" || done {
        VerificationStatus::Failed
    } else {
        VerificationStatus::Continue
    }
}

/// Verify a print enrolled in fprintd for `username`.
///
/// Any unavailable service, reader, enrollment, authorization, or failed scan
/// returns `false`, allowing the caller to continue with the Hello PIN prompt.
pub fn verify_fingerprint(username: &str) -> bool {
    let result = (|| -> zbus::Result<bool> {
        let connection = Connection::system()?;
        let manager = Proxy::new(
            &connection,
            FPRINTD_DESTINATION,
            FPRINTD_MANAGER_PATH,
            FPRINTD_MANAGER_INTERFACE,
        )?;
        let device_path: OwnedObjectPath = manager.call("GetDefaultDevice", &())?;
        let device = Proxy::new(
            &connection,
            FPRINTD_DESTINATION,
            device_path,
            FPRINTD_DEVICE_INTERFACE,
        )?;

        let _: () = device.call("Claim", &(username,))?;
        let mut started = false;
        let verification = (|| -> zbus::Result<bool> {
            // Subscribe before starting verification so a fast reader cannot
            // emit its terminal status before we begin listening.
            let mut statuses = device.receive_signal("VerifyStatus")?;
            let _: () = device.call("VerifyStart", &("any",))?;
            started = true;

            for signal in &mut statuses {
                let (status, done): (String, bool) = signal.body().deserialize()?;
                match verification_status(&status, done) {
                    VerificationStatus::Matched => return Ok(true),
                    VerificationStatus::Failed => return Ok(false),
                    VerificationStatus::Continue => continue,
                }
            }

            Ok(false)
        })();

        if started {
            let _: Result<(), _> = device.call("VerifyStop", &());
        }
        let _: Result<(), _> = device.call("Release", &());
        verification
    })();

    match result {
        Ok(matched) => matched,
        Err(err) => {
            debug!(
                ?err,
                "fprintd verification unavailable; falling back to Hello PIN"
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{verification_status, VerificationStatus};

    #[test]
    fn match_is_successful_even_when_terminal() {
        assert_eq!(
            verification_status("verify-match", true),
            VerificationStatus::Matched
        );
    }

    #[test]
    fn retry_is_not_a_terminal_failure() {
        assert_eq!(
            verification_status("verify-retry-scan", false),
            VerificationStatus::Continue
        );
    }

    #[test]
    fn non_match_falls_back_without_waiting_for_a_terminal_signal() {
        assert_eq!(
            verification_status("verify-no-match", false),
            VerificationStatus::Failed
        );
    }
}
