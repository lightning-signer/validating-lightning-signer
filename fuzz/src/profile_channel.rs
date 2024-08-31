use vls_fuzz::channel::{Action, ChannelFuzz};

// NOTE: this requires cfg(fuzzing) to be set
fn main() {
	// benchmark validation and revocation
	let mut channel_fuzz = ChannelFuzz::new();
	for _ in 0..10000 {
		channel_fuzz.run(vec![
			Action::Revoke,
			Action::Revoke,
			Action::Revoke,
			Action::Revoke,
			Action::Revoke,
			Action::Revoke,
			Action::Revoke,
			Action::Revoke,
			Action::Revoke,
			Action::Revoke,
		]).unwrap();
	}
}
