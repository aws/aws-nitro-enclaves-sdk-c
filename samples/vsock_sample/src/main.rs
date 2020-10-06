use clap::{App, AppSettings, Arg, SubCommand};

use vsock_sample::command_parser::{ClientArgs, ServerArgs};
use vsock_sample::create_app;
use vsock_sample::utils::ExitGracefully;
use vsock_sample::{client, server};

fn main() {
    let app = create_app!();
    let args = app.get_matches();

    match args.subcommand() {
        ("server", Some(args)) => {
            let server_args = ServerArgs::new_with(args).ok_or_exit(args.usage());
            server(server_args).ok_or_exit(args.usage());
        }
        ("client", Some(args)) => {
            let client_args = ClientArgs::new_with(args).ok_or_exit(args.usage());
            client(client_args).ok_or_exit(args.usage());
        }
        (&_, _) => {}
    }
}
