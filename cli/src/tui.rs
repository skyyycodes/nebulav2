use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Gauge, List, ListItem, Paragraph, Wrap},
    DefaultTerminal, Frame,
};

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(PartialEq)]
enum Screen {
    Dashboard,
    Send,
}

#[derive(PartialEq)]
enum SendStep {
    InputTo,
    InputAmount,
    Confirm,
    Proving { started: std::time::Instant, elapsed: u64 },
    Submitting,
    Done(String),
    Error(String),
}

pub struct WalletInfo {
    pub pubkey_hash: String,
    pub balance_stroops: i64,
    pub nonce: u32,
    pub leaves_used: u32,
    pub leaves_total: u32,
}

pub struct TxHistory {
    pub amount_stroops: i64,
    pub destination: String,
    pub nonce: u32,
}

struct App {
    screen: Screen,
    wallet: WalletInfo,
    history: Vec<TxHistory>,
    // send wizard state
    send_to: String,
    send_amount: String,
    send_step: SendStep,
    send_error: Option<String>,
}

impl App {
    fn new(wallet: WalletInfo, history: Vec<TxHistory>) -> Self {
        Self {
            screen: Screen::Dashboard,
            wallet,
            history,
            send_to: String::new(),
            send_amount: String::new(),
            send_step: SendStep::InputTo,
            send_error: None,
        }
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

pub fn run_tui(
    wallet: WalletInfo,
    history: Vec<TxHistory>,
    withdraw_fn: impl Fn(&str, i64) -> Result<String>,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let terminal = ratatui::init();
    let result = run_app(terminal, wallet, history, withdraw_fn);
    ratatui::restore();
    disable_raw_mode()?;
    execute!(std::io::stdout(), LeaveAlternateScreen)?;
    result
}

fn run_app(
    mut terminal: DefaultTerminal,
    wallet: WalletInfo,
    history: Vec<TxHistory>,
    withdraw_fn: impl Fn(&str, i64) -> Result<String>,
) -> Result<()> {
    let mut app = App::new(wallet, history);

    loop {
        terminal.draw(|f| draw(f, &app))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press { continue; }

                match app.screen {
                    Screen::Dashboard => match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => break,
                        KeyCode::Char('s') | KeyCode::Char('S') => {
                            app.screen = Screen::Send;
                            app.send_step = SendStep::InputTo;
                            app.send_to.clear();
                            app.send_amount.clear();
                            app.send_error = None;
                        }
                        _ => {}
                    },
                    Screen::Send => match &app.send_step {
                        SendStep::InputTo => match key.code {
                            KeyCode::Esc => { app.screen = Screen::Dashboard; }
                            KeyCode::Enter => {
                                if !app.send_to.is_empty() {
                                    app.send_step = SendStep::InputAmount;
                                }
                            }
                            KeyCode::Backspace => { app.send_to.pop(); }
                            KeyCode::Char(c) => { app.send_to.push(c); }
                            _ => {}
                        },
                        SendStep::InputAmount => match key.code {
                            KeyCode::Esc => { app.send_step = SendStep::InputTo; }
                            KeyCode::Enter => {
                                if !app.send_amount.is_empty() {
                                    app.send_step = SendStep::Confirm;
                                }
                            }
                            KeyCode::Backspace => { app.send_amount.pop(); }
                            KeyCode::Char(c) if c.is_ascii_digit() || c == '.' => {
                                app.send_amount.push(c);
                            }
                            _ => {}
                        },
                        SendStep::Confirm => match key.code {
                            KeyCode::Esc => { app.send_step = SendStep::InputAmount; }
                            KeyCode::Enter => {
                                // parse amount as XLM → stroops
                                let amount_xlm: f64 = app.send_amount.parse().unwrap_or(0.0);
                                let amount_stroops = (amount_xlm * 10_000_000.0) as i64;
                                let to = app.send_to.clone();

                                app.send_step = SendStep::Proving {
                                    started: Instant::now(),
                                    elapsed: 0,
                                };

                                // Run withdraw (blocking — in a real app this would be a thread)
                                // We redraw once before blocking
                                terminal.draw(|f| draw(f, &app))?;

                                match withdraw_fn(&to, amount_stroops) {
                                    Ok(tx_hash) => {
                                        app.send_step = SendStep::Done(tx_hash);
                                        // Update balance optimistically
                                        app.wallet.balance_stroops -= amount_stroops;
                                        app.wallet.nonce += 1;
                                        app.wallet.leaves_used += 1;
                                        app.history.insert(0, TxHistory {
                                            amount_stroops,
                                            destination: to,
                                            nonce: app.wallet.nonce - 1,
                                        });
                                    }
                                    Err(e) => {
                                        app.send_step = SendStep::Error(e.to_string());
                                    }
                                }
                            }
                            _ => {}
                        },
                        SendStep::Done(_) | SendStep::Error(_) => match key.code {
                            KeyCode::Enter | KeyCode::Esc => {
                                app.screen = Screen::Dashboard;
                            }
                            _ => {}
                        },
                        _ => {}
                    },
                }
            }
        }

        // Tick proving elapsed time
        if let SendStep::Proving { started, ref mut elapsed } = app.send_step {
            *elapsed = started.elapsed().as_secs();
        }
    }

    Ok(())
}

// ── Drawing ───────────────────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &App) {
    match app.screen {
        Screen::Dashboard => draw_dashboard(f, app),
        Screen::Send => draw_send(f, app),
    }
}

fn draw_dashboard(f: &mut Frame, app: &App) {
    let area = f.area();

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Line::from(vec![
            Span::styled(" ⬡ NEBULA WALLET ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]))
        .title_alignment(Alignment::Left);

    let inner = outer.inner(area);
    f.render_widget(outer, area);

    // Tag top-right
    let tag = Paragraph::new("[testnet]")
        .style(Style::default().fg(Color::Yellow));
    let tag_area = Rect { x: area.x + area.width - 12, y: area.y, width: 11, height: 1 };
    f.render_widget(tag, tag_area);

    // Split inner into: stats(5) | history(rest) | keys(1)
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // stats row
            Constraint::Min(4),     // history
            Constraint::Length(1),  // hotkeys
        ])
        .split(inner);

    // ── Stats row ─────────────────────────────────────────────────────────────
    let stats_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(34),
        ])
        .split(rows[0]);

    // Balance
    let xlm = app.wallet.balance_stroops as f64 / 10_000_000.0;
    let balance_block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)).title(" Balance ");
    let balance_inner = balance_block.inner(stats_cols[0]);
    f.render_widget(balance_block, stats_cols[0]);
    f.render_widget(
        Paragraph::new(format!("◎ {:.2} XLM", xlm))
            .style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center),
        balance_inner,
    );

    // Nonce
    let nonce_block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)).title(" Nonce ");
    let nonce_inner = nonce_block.inner(stats_cols[1]);
    f.render_widget(nonce_block, stats_cols[1]);
    f.render_widget(
        Paragraph::new(format!("{}", app.wallet.nonce))
            .style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center),
        nonce_inner,
    );

    // XMSS leaves
    let leaves_block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)).title(" XMSS Leaves ");
    let leaves_inner = leaves_block.inner(stats_cols[2]);
    f.render_widget(leaves_block, stats_cols[2]);

    let used = app.wallet.leaves_used;
    let total = app.wallet.leaves_total;
    let ratio = used as f64 / total as f64;
    let color = if ratio > 0.8 { Color::Red } else if ratio > 0.5 { Color::Yellow } else { Color::Green };

    let gauge_area = Rect { x: leaves_inner.x, y: leaves_inner.y, width: leaves_inner.width, height: 1 };
    let label_area = Rect { x: leaves_inner.x, y: leaves_inner.y + 1, width: leaves_inner.width, height: 1 };

    f.render_widget(
        Gauge::default()
            .gauge_style(Style::default().fg(color))
            .ratio(ratio)
            .label(format!("{}/{}", used, total)),
        gauge_area,
    );
    let remaining = total - used;
    f.render_widget(
        Paragraph::new(format!("{} remaining", remaining))
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center),
        label_area,
    );

    // ── History ───────────────────────────────────────────────────────────────
    let history_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Recent Activity ");
    let history_inner = history_block.inner(rows[1]);
    f.render_widget(history_block, rows[1]);

    if app.history.is_empty() {
        f.render_widget(
            Paragraph::new("No transactions yet.")
                .style(Style::default().fg(Color::DarkGray))
                .alignment(Alignment::Center),
            history_inner,
        );
    } else {
        let items: Vec<ListItem> = app.history.iter().map(|tx| {
            let xlm = tx.amount_stroops as f64 / 10_000_000.0;
            let dest = if tx.destination.len() > 20 {
                format!("{}...{}", &tx.destination[..8], &tx.destination[tx.destination.len()-6..])
            } else {
                tx.destination.clone()
            };
            ListItem::new(Line::from(vec![
                Span::styled("✓ ", Style::default().fg(Color::Green)),
                Span::styled(format!("-{:.2} XLM", xlm), Style::default().fg(Color::White)),
                Span::raw(" → "),
                Span::styled(dest, Style::default().fg(Color::Cyan)),
                Span::raw(format!("   nonce {}", tx.nonce)),
            ]))
        }).collect();

        f.render_widget(List::new(items), history_inner);
    }

    // ── Hotkeys ───────────────────────────────────────────────────────────────
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" [s]", Style::default().fg(Color::Yellow)),
            Span::raw(" send    "),
            Span::styled("[r]", Style::default().fg(Color::Yellow)),
            Span::raw(" refresh    "),
            Span::styled("[q]", Style::default().fg(Color::Yellow)),
            Span::raw(" quit"),
        ])),
        rows[2],
    );
}

fn draw_send(f: &mut Frame, app: &App) {
    let area = f.area();

    // Center a 60-wide, 20-tall box
    let popup_w = 62u16.min(area.width);
    let popup_h = 20u16.min(area.height);
    let popup_area = Rect {
        x: area.x + (area.width.saturating_sub(popup_w)) / 2,
        y: area.y + (area.height.saturating_sub(popup_h)) / 2,
        width: popup_w,
        height: popup_h,
    };

    // Dim background
    f.render_widget(Clear, popup_area);

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Line::from(vec![
            Span::styled(" ⬡ SEND XLM ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]));

    let inner = outer.inner(popup_area);
    f.render_widget(outer, popup_area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // To field
            Constraint::Length(3), // Amount field
            Constraint::Length(1), // spacer
            Constraint::Min(4),    // status / progress
            Constraint::Length(1), // hotkeys
        ])
        .split(inner);

    // ── To field ──────────────────────────────────────────────────────────────
    let to_active = matches!(app.send_step, SendStep::InputTo);
    let to_style = if to_active { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) };
    let to_block = Block::default().borders(Borders::ALL).border_style(to_style).title(" To (G...) ");
    let to_inner = to_block.inner(rows[0]);
    f.render_widget(to_block, rows[0]);
    let to_display = if to_active {
        format!("{}█", app.send_to)
    } else if app.send_to.is_empty() {
        String::new()
    } else {
        app.send_to.clone()
    };
    f.render_widget(Paragraph::new(to_display).style(Style::default().fg(Color::White)), to_inner);

    // ── Amount field ──────────────────────────────────────────────────────────
    let amt_active = matches!(app.send_step, SendStep::InputAmount);
    let amt_style = if amt_active { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) };
    let amt_block = Block::default().borders(Borders::ALL).border_style(amt_style).title(" Amount (XLM) ");
    let amt_inner = amt_block.inner(rows[1]);
    f.render_widget(amt_block, rows[1]);
    let amt_display = if amt_active {
        format!("{}█", app.send_amount)
    } else {
        app.send_amount.clone()
    };
    f.render_widget(Paragraph::new(amt_display).style(Style::default().fg(Color::White)), amt_inner);

    // ── Status area ───────────────────────────────────────────────────────────
    let status_area = rows[3];
    match &app.send_step {
        SendStep::InputTo | SendStep::InputAmount => {
            f.render_widget(
                Paragraph::new("Fill in the fields above, then press [enter]")
                    .style(Style::default().fg(Color::DarkGray))
                    .alignment(Alignment::Center),
                status_area,
            );
        }
        SendStep::Confirm => {
            let xlm: f64 = app.send_amount.parse().unwrap_or(0.0);
            let dest = if app.send_to.len() > 30 {
                format!("{}...{}", &app.send_to[..10], &app.send_to[app.send_to.len()-8..])
            } else {
                app.send_to.clone()
            };
            let lines = vec![
                Line::from(vec![Span::styled("  Confirm withdrawal", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))]),
                Line::from(""),
                Line::from(vec![
                    Span::raw("  Send: "),
                    Span::styled(format!("{:.7} XLM", xlm), Style::default().fg(Color::Green)),
                ]),
                Line::from(vec![
                    Span::raw("    To: "),
                    Span::styled(dest, Style::default().fg(Color::Cyan)),
                ]),
            ];
            f.render_widget(Paragraph::new(lines), status_area);
        }
        SendStep::Proving { elapsed, .. } => {
            let secs = *elapsed;
            // Estimated ~60s for proving
            let ratio = (secs as f64 / 60.0).min(0.95);
            let gauge_area = Rect { x: status_area.x, y: status_area.y + 1, width: status_area.width, height: 1 };
            let label_area = Rect { x: status_area.x, y: status_area.y + 2, width: status_area.width, height: 1 };

            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("● ", Style::default().fg(Color::Yellow)),
                    Span::raw("Generating ZK proof via Sindri..."),
                ])),
                Rect { x: status_area.x, y: status_area.y, width: status_area.width, height: 1 },
            );

            f.render_widget(
                Gauge::default()
                    .gauge_style(Style::default().fg(Color::Cyan))
                    .ratio(ratio)
                    .label(format!("{}s", secs)),
                gauge_area,
            );

            f.render_widget(
                Paragraph::new("This takes ~60 seconds. Please wait...")
                    .style(Style::default().fg(Color::DarkGray))
                    .alignment(Alignment::Center),
                label_area,
            );
        }
        SendStep::Submitting => {
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("● ", Style::default().fg(Color::Yellow)),
                    Span::raw("Submitting to Stellar..."),
                ])),
                status_area,
            );
        }
        SendStep::Done(tx) => {
            let short_tx = if tx.len() > 20 { format!("{}...", &tx[..20]) } else { tx.clone() };
            let lines = vec![
                Line::from(vec![Span::styled("✓ Withdrawal complete!", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))]),
                Line::from(""),
                Line::from(vec![Span::raw(format!("  tx: {}", short_tx))]),
            ];
            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), status_area);
        }
        SendStep::Error(e) => {
            let lines = vec![
                Line::from(vec![Span::styled("✗ Error", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))]),
                Line::from(""),
                Line::from(vec![Span::raw(e.as_str())]),
            ];
            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), status_area);
        }
    }

    // ── Hotkeys ───────────────────────────────────────────────────────────────
    let hotkeys = match &app.send_step {
        SendStep::Confirm => Line::from(vec![
            Span::styled(" [enter]", Style::default().fg(Color::Green)),
            Span::raw(" confirm    "),
            Span::styled("[esc]", Style::default().fg(Color::Yellow)),
            Span::raw(" back"),
        ]),
        SendStep::Done(_) | SendStep::Error(_) => Line::from(vec![
            Span::styled(" [enter]", Style::default().fg(Color::Green)),
            Span::raw(" / "),
            Span::styled("[esc]", Style::default().fg(Color::Yellow)),
            Span::raw(" back to dashboard"),
        ]),
        _ => Line::from(vec![
            Span::styled(" [enter]", Style::default().fg(Color::Green)),
            Span::raw(" next    "),
            Span::styled("[esc]", Style::default().fg(Color::Yellow)),
            Span::raw(" back"),
        ]),
    };
    f.render_widget(Paragraph::new(hotkeys), rows[4]);
}
