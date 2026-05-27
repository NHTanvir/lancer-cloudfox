use anyhow::{Context, Result};
use colored::Colorize;
use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Terminal;
use serde::Deserialize;
use std::fs;
use std::io;
use std::path::Path;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

#[derive(Debug, Deserialize, Clone)]
struct CapeRow {
    #[serde(default)]
    external_account: String,
    #[serde(default)]
    entry_role_arn: String,
    #[serde(default)]
    target_role_arn: String,
    #[serde(default)]
    chain_length: usize,
    #[serde(default)]
    contains_admin: bool,
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter) -> Result<()> {
    let cape_json = output.base_dir().join("table").join("cape.json");

    if !cape_json.exists() {
        println!(
            "{} {} not found — running `cape` to populate it.",
            "[cape-tui]".cyan().bold(),
            cape_json.display()
        );
        crate::aws::cape::run(factory, output).await?;
    }

    let rows = load_rows(&cape_json)
        .with_context(|| format!("failed to load cape.json at {}", cape_json.display()))?;

    if rows.is_empty() {
        println!(
            "{} No attack chains found. Nothing to display.",
            "[cape-tui]".yellow().bold()
        );
        return Ok(());
    }

    render(rows)?;
    Ok(())
}

fn load_rows(path: &Path) -> Result<Vec<CapeRow>> {
    let body = fs::read_to_string(path)?;
    let parsed: Vec<CapeRow> = serde_json::from_str(&body)?;
    Ok(parsed)
}

fn render(rows: Vec<CapeRow>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, rows);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    result
}

fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    rows: Vec<CapeRow>,
) -> Result<()> {
    let mut state = TableState::default();
    state.select(Some(0));

    loop {
        terminal.draw(|f| draw(f, &rows, &mut state))?;

        if event::poll(std::time::Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j') => {
                        let idx = state.selected().unwrap_or(0);
                        let next = (idx + 1).min(rows.len().saturating_sub(1));
                        state.select(Some(next));
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        let idx = state.selected().unwrap_or(0);
                        state.select(Some(idx.saturating_sub(1)));
                    }
                    KeyCode::Home | KeyCode::Char('g') => state.select(Some(0)),
                    KeyCode::End | KeyCode::Char('G') => {
                        state.select(Some(rows.len().saturating_sub(1)))
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn draw(f: &mut ratatui::Frame, rows: &[CapeRow], state: &mut TableState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(8),
            Constraint::Length(7),
            Constraint::Length(1),
        ])
        .split(f.area());

    let header_cells = ["ExternalAccount", "EntryRoleArn", "TargetRoleArn", "Len", "Admin"]
        .into_iter()
        .map(|h| Span::styled(h, Style::default().add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).style(Style::default().fg(Color::Cyan));

    let body_rows: Vec<Row> = rows
        .iter()
        .map(|r| {
            let admin_span = if r.contains_admin {
                Span::styled("YES", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
            } else {
                Span::raw("no")
            };
            Row::new(vec![
                Span::raw(r.external_account.clone()),
                Span::raw(r.entry_role_arn.clone()),
                Span::raw(r.target_role_arn.clone()),
                Span::raw(r.chain_length.to_string()),
                admin_span,
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(18),
        Constraint::Percentage(35),
        Constraint::Percentage(35),
        Constraint::Length(5),
        Constraint::Length(6),
    ];

    let table = Table::new(body_rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Cape — Cross-Account Attack Chains "),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(table, chunks[0], state);

    let selected = state.selected().and_then(|i| rows.get(i));
    let detail_lines: Vec<Line> = if let Some(r) = selected {
        vec![
            Line::from(vec![
                Span::styled("External Account: ", Style::default().fg(Color::Yellow)),
                Span::raw(r.external_account.clone()),
            ]),
            Line::from(vec![
                Span::styled("Entry Role:       ", Style::default().fg(Color::Yellow)),
                Span::raw(r.entry_role_arn.clone()),
            ]),
            Line::from(vec![
                Span::styled("Target Role:      ", Style::default().fg(Color::Yellow)),
                Span::raw(r.target_role_arn.clone()),
            ]),
            Line::from(vec![
                Span::styled("Chain Length:     ", Style::default().fg(Color::Yellow)),
                Span::raw(r.chain_length.to_string()),
            ]),
            Line::from(vec![
                Span::styled("Contains Admin:   ", Style::default().fg(Color::Yellow)),
                if r.contains_admin {
                    Span::styled("YES", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
                } else {
                    Span::raw("no")
                },
            ]),
        ]
    } else {
        vec![Line::from("No selection")]
    };

    let detail = Paragraph::new(detail_lines)
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL).title(" Detail "));
    f.render_widget(detail, chunks[1]);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" q/Esc ", Style::default().bg(Color::DarkGray)),
        Span::raw(" quit  "),
        Span::styled(" ↑↓/jk ", Style::default().bg(Color::DarkGray)),
        Span::raw(" navigate  "),
        Span::styled(" g/G ", Style::default().bg(Color::DarkGray)),
        Span::raw(" top/bottom"),
    ]));
    f.render_widget(footer, chunks[2]);
}
