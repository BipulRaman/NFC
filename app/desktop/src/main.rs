#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use nfc_studio::apdu::{self, KeyType};
use nfc_studio::card::{CardInfo, Reader};
use nfc_studio::ndef;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 680.0])
            .with_min_inner_size([640.0, 480.0]),
        ..Default::default()
    };
    eframe::run_native(
        "NFC Studio",
        options,
        Box::new(|_cc| Ok(Box::new(App::new()))),
    )
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Apdu,
    Classic,
    Ultralight,
    Ndef,
}

#[derive(PartialEq, Clone, Copy)]
enum NdefKind {
    Text,
    Uri,
}

struct App {
    reader: Option<Reader>,
    readers: Vec<String>,
    selected: usize,
    info: Option<CardInfo>,
    tab: Tab,
    log: Vec<String>,

    apdu_input: String,

    key_hex: String,
    key_type: KeyType,
    block: u8,
    block_data: String,
    allow_trailer: bool,

    page: u8,
    page_data: String,

    ndef_kind: NdefKind,
    ndef_text: String,
    ndef_lang: String,
    ndef_result: String,
}

impl App {
    fn new() -> Self {
        let mut app = Self {
            reader: None,
            readers: Vec::new(),
            selected: 0,
            info: None,
            tab: Tab::Apdu,
            log: Vec::new(),
            apdu_input: "FF CA 00 00 00".into(),
            key_hex: "FFFFFFFFFFFF".into(),
            key_type: KeyType::A,
            block: 4,
            block_data: String::new(),
            allow_trailer: false,
            page: 4,
            page_data: String::new(),
            ndef_kind: NdefKind::Text,
            ndef_text: "Hello from NFC Studio".into(),
            ndef_lang: "en".into(),
            ndef_result: String::new(),
        };
        match Reader::new() {
            Ok(r) => {
                app.reader = Some(r);
                app.refresh();
            }
            Err(e) => app.log(format!("PC/SC unavailable: {e}")),
        }
        app
    }

    fn log(&mut self, msg: impl Into<String>) {
        self.log.push(msg.into());
        if self.log.len() > 500 {
            self.log.drain(..100);
        }
    }

    fn refresh(&mut self) {
        let Some(reader) = &self.reader else { return };
        match reader.list_readers() {
            Ok(list) => {
                self.log(format!("Found {} reader(s)", list.len()));
                self.readers = list;
                if self.selected >= self.readers.len() {
                    self.selected = 0;
                }
            }
            Err(e) => {
                self.readers.clear();
                self.log(format!("List readers: {e}"));
            }
        }
    }

    fn connect(&mut self) {
        let Some(name) = self.readers.get(self.selected).cloned() else {
            self.log("No reader selected");
            return;
        };
        let Some(reader) = self.reader.as_mut() else { return };
        match reader.connect(&name) {
            Ok(info) => {
                let msg = format!(
                    "Connected: {} | ATR {} | UID {}",
                    info.kind.label(),
                    apdu::to_hex(&info.atr),
                    info.uid.as_deref().map(apdu::to_hex).unwrap_or_else(|| "?".into())
                );
                self.info = Some(info);
                self.log(msg);
            }
            Err(e) => {
                self.info = None;
                self.log(format!("Connect failed: {e}"));
            }
        }
    }

    fn disconnect(&mut self) {
        if let Some(r) = self.reader.as_mut() {
            r.disconnect();
        }
        self.info = None;
        self.log("Disconnected");
    }

    fn transmit(&mut self, cmd: &[u8]) -> Result<Vec<u8>, String> {
        let reader = self.reader.as_ref().ok_or("PC/SC unavailable")?;
        if !reader.is_connected() {
            return Err("No card connected".into());
        }
        let resp = reader.transmit(cmd);
        match &resp {
            Ok(r) => self.log(format!(">> {}\n<< {}", apdu::to_hex(cmd), apdu::to_hex(r))),
            Err(e) => self.log(format!(">> {}\n!! {e}", apdu::to_hex(cmd))),
        }
        resp
    }

    fn transmit_ok(&mut self, cmd: &[u8]) -> Result<Vec<u8>, String> {
        let resp = self.transmit(cmd)?;
        apdu::expect_ok(&resp)
    }

    // ---- MIFARE Classic -------------------------------------------------

    fn classic_auth(&mut self, block: u8) -> Result<(), String> {
        let key = apdu::parse_hex(&self.key_hex)?;
        let key: [u8; 6] = key
            .try_into()
            .map_err(|_| "Key must be exactly 6 bytes".to_string())?;
        self.transmit_ok(&apdu::load_key(0, &key))?;
        self.transmit_ok(&apdu::authenticate(block, self.key_type, 0))?;
        Ok(())
    }

    fn classic_read_block(&mut self) {
        let block = self.block;
        let r = self
            .classic_auth(block)
            .and_then(|_| self.transmit_ok(&apdu::read_binary(block, 16)));
        match r {
            Ok(data) => {
                self.block_data = apdu::to_hex(&data);
                self.log(format!("Block {block}: {} |{}|", apdu::to_hex(&data), apdu::to_ascii(&data)));
            }
            Err(e) => self.log(format!("Read block {block} failed: {e}")),
        }
    }

    fn classic_read_sector(&mut self) {
        let first = self.block - self.block % 4;
        if let Err(e) = self.classic_auth(first) {
            self.log(format!("Auth sector {} failed: {e}", first / 4));
            return;
        }
        for b in first..first + 4 {
            match self.transmit_ok(&apdu::read_binary(b, 16)) {
                Ok(d) => self.log(format!("Block {b:>3}: {} |{}|", apdu::to_hex(&d), apdu::to_ascii(&d))),
                Err(e) => self.log(format!("Block {b:>3}: {e}")),
            }
        }
    }

    fn classic_write_block(&mut self) {
        let block = self.block;
        if block == 0 {
            self.log("Refusing to write block 0 (manufacturer block)");
            return;
        }
        if apdu::is_sector_trailer(block) && !self.allow_trailer {
            self.log("Block is a sector trailer; tick the confirmation box to write it");
            return;
        }
        let data = match apdu::parse_hex(&self.block_data) {
            Ok(d) if d.len() == 16 => d,
            Ok(d) => {
                self.log(format!("Block data must be 16 bytes (got {})", d.len()));
                return;
            }
            Err(e) => {
                self.log(e);
                return;
            }
        };
        let r = self
            .classic_auth(block)
            .and_then(|_| self.transmit_ok(&apdu::update_binary(block, &data)));
        match r {
            Ok(_) => self.log(format!("Wrote block {block}")),
            Err(e) => self.log(format!("Write block {block} failed: {e}")),
        }
    }

    // ---- NTAG / Ultralight ---------------------------------------------

    fn ul_read(&mut self) {
        let page = self.page;
        match self.transmit_ok(&apdu::read_binary(page, 16)) {
            Ok(d) => {
                self.page_data = apdu::to_hex(&d[..d.len().min(4)]);
                for (i, chunk) in d.chunks(4).enumerate() {
                    self.log(format!(
                        "Page {:>3}: {} |{}|",
                        page as usize + i,
                        apdu::to_hex(chunk),
                        apdu::to_ascii(chunk)
                    ));
                }
            }
            Err(e) => self.log(format!("Read page {page} failed: {e}")),
        }
    }

    fn ul_write(&mut self) {
        let page = self.page;
        if page < 4 {
            self.log("Pages 0-3 hold UID/lock/OTP bits; writing them is refused");
            return;
        }
        let data = match apdu::parse_hex(&self.page_data) {
            Ok(d) if d.len() == 4 => d,
            Ok(d) => {
                self.log(format!("Page data must be 4 bytes (got {})", d.len()));
                return;
            }
            Err(e) => {
                self.log(e);
                return;
            }
        };
        match self.transmit_ok(&apdu::update_binary(page, &data)) {
            Ok(_) => self.log(format!("Wrote page {page}")),
            Err(e) => self.log(format!("Write page {page} failed: {e}")),
        }
    }

    // ---- NDEF (Type 2 tags) --------------------------------------------

    fn ndef_read(&mut self) {
        let mut mem = Vec::new();
        // Read up to 256 bytes of user memory starting at page 4.
        for i in 0..16u8 {
            match self.transmit_ok(&apdu::read_binary(4 + i * 4, 16)) {
                Ok(d) => {
                    mem.extend_from_slice(&d);
                    if ndef::find_ndef_tlv(&mem).is_ok() || mem.contains(&0xFE) {
                        break;
                    }
                }
                Err(e) => {
                    if mem.is_empty() {
                        self.log(format!("NDEF read failed: {e}"));
                        return;
                    }
                    break;
                }
            }
        }
        match ndef::find_ndef_tlv(&mem).and_then(|m| ndef::decode_message(&m)) {
            Ok(records) if records.is_empty() => {
                self.ndef_result = "(empty NDEF message)".into();
            }
            Ok(records) => {
                self.ndef_result = records
                    .iter()
                    .enumerate()
                    .map(|(i, r)| format!("#{}: {r}", i + 1))
                    .collect::<Vec<_>>()
                    .join("\n");
            }
            Err(e) => self.ndef_result = format!("No NDEF data: {e}"),
        }
        let msg = format!("NDEF read:\n{}", self.ndef_result);
        self.log(msg);
    }

    fn ndef_write(&mut self) {
        let record = match self.ndef_kind {
            NdefKind::Text => ndef::text_record(&self.ndef_text, &self.ndef_lang),
            NdefKind::Uri => ndef::uri_record(&self.ndef_text),
        };
        let mut bytes = ndef::wrap_tlv(&ndef::encode_message(&[record]));
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
        for (i, chunk) in bytes.chunks(4).enumerate() {
            let page = 4 + i as u8;
            if let Err(e) = self.transmit_ok(&apdu::update_binary(page, chunk)) {
                self.log(format!("NDEF write failed at page {page}: {e}"));
                return;
            }
        }
        self.log(format!("NDEF written ({} bytes)", bytes.len()));
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("reader").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Reader:");
                let current = self
                    .readers
                    .get(self.selected)
                    .cloned()
                    .unwrap_or_else(|| "(none)".into());
                egui::ComboBox::from_id_salt("reader_combo")
                    .width(320.0)
                    .selected_text(current)
                    .show_ui(ui, |ui| {
                        for (i, r) in self.readers.iter().enumerate() {
                            ui.selectable_value(&mut self.selected, i, r);
                        }
                    });
                if ui.button("⟳ Refresh").clicked() {
                    self.refresh();
                }
                let connected = self.info.is_some();
                if ui
                    .add_enabled(!connected && !self.readers.is_empty(), egui::Button::new("Connect"))
                    .clicked()
                {
                    self.connect();
                }
                if ui.add_enabled(connected, egui::Button::new("Disconnect")).clicked() {
                    self.disconnect();
                }
            });
            if let Some(info) = &self.info {
                ui.horizontal_wrapped(|ui| {
                    ui.strong(info.kind.label());
                    ui.label(format!("ATR: {}", apdu::to_hex(&info.atr)));
                    ui.label(format!(
                        "UID: {}",
                        info.uid.as_deref().map(apdu::to_hex).unwrap_or_else(|| "?".into())
                    ));
                });
            } else {
                ui.weak("Place a card on the reader and press Connect.");
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Apdu, "APDU console");
                ui.selectable_value(&mut self.tab, Tab::Classic, "MIFARE Classic");
                ui.selectable_value(&mut self.tab, Tab::Ultralight, "NTAG / Ultralight");
                ui.selectable_value(&mut self.tab, Tab::Ndef, "NDEF");
            });
            ui.add_space(2.0);
        });

        egui::TopBottomPanel::bottom("log")
            .resizable(true)
            .default_height(220.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.strong("Log");
                    if ui.small_button("Clear").clicked() {
                        self.log.clear();
                    }
                });
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for line in &self.log {
                            ui.monospace(line);
                        }
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Apdu => {
                ui.label("Command APDU (hex):");
                ui.add(egui::TextEdit::singleline(&mut self.apdu_input).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
                ui.horizontal(|ui| {
                    if ui.button("Send").clicked() {
                        match apdu::parse_hex(&self.apdu_input) {
                            Ok(cmd) => {
                                if let Ok(resp) = self.transmit(&cmd) {
                                    if let Ok((_, sw)) = apdu::split_sw(&resp) {
                                        self.log(format!("SW {sw:04X}: {}", apdu::describe_sw(sw)));
                                    }
                                }
                            }
                            Err(e) => self.log(e),
                        }
                    }
                    for (label, cmd) in [
                        ("Get UID", "FF CA 00 00 00"),
                        ("Get ATS", "FF CA 01 00 00"),
                        ("Select PPSE", "00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00"),
                    ] {
                        if ui.small_button(label).clicked() {
                            self.apdu_input = cmd.into();
                        }
                    }
                });
            }
            Tab::Classic => {
                egui::Grid::new("classic").num_columns(2).show(ui, |ui| {
                    ui.label("Key (6 bytes hex):");
                    ui.text_edit_singleline(&mut self.key_hex);
                    ui.end_row();
                    ui.label("Key type:");
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.key_type, KeyType::A, "A");
                        ui.radio_value(&mut self.key_type, KeyType::B, "B");
                    });
                    ui.end_row();
                    ui.label("Block:");
                    ui.horizontal(|ui| {
                        ui.add(egui::DragValue::new(&mut self.block).range(0..=255));
                        ui.weak(format!(
                            "sector {}{}",
                            self.block / 4,
                            if apdu::is_sector_trailer(self.block) { " (trailer)" } else { "" }
                        ));
                    });
                    ui.end_row();
                    ui.label("Data (16 bytes hex):");
                    ui.add(egui::TextEdit::singleline(&mut self.block_data).font(egui::TextStyle::Monospace).desired_width(420.0));
                    ui.end_row();
                });
                ui.weak("Blocks ≥128 on 4K cards use 16-block sectors; sector read covers 4-block sectors.");
                ui.horizontal(|ui| {
                    if ui.button("Read block").clicked() {
                        self.classic_read_block();
                    }
                    if ui.button("Read sector").clicked() {
                        self.classic_read_sector();
                    }
                    if ui.button("Write block").clicked() {
                        self.classic_write_block();
                    }
                });
                ui.checkbox(
                    &mut self.allow_trailer,
                    "I understand writing a sector trailer can permanently lock the sector",
                );
            }
            Tab::Ultralight => {
                egui::Grid::new("ul").num_columns(2).show(ui, |ui| {
                    ui.label("Page:");
                    ui.add(egui::DragValue::new(&mut self.page).range(0..=255));
                    ui.end_row();
                    ui.label("Data (4 bytes hex):");
                    ui.add(egui::TextEdit::singleline(&mut self.page_data).font(egui::TextStyle::Monospace));
                    ui.end_row();
                });
                ui.horizontal(|ui| {
                    if ui.button("Read 4 pages").clicked() {
                        self.ul_read();
                    }
                    if ui.button("Write page").clicked() {
                        self.ul_write();
                    }
                });
                ui.weak("Pages 0–3 (UID, lock bytes, capability container) are protected.");
            }
            Tab::Ndef => {
                ui.horizontal(|ui| {
                    ui.radio_value(&mut self.ndef_kind, NdefKind::Text, "Text");
                    ui.radio_value(&mut self.ndef_kind, NdefKind::Uri, "URI");
                    if self.ndef_kind == NdefKind::Text {
                        ui.label("Lang:");
                        ui.add(egui::TextEdit::singleline(&mut self.ndef_lang).desired_width(40.0));
                    }
                });
                ui.add(egui::TextEdit::multiline(&mut self.ndef_text).desired_rows(2).desired_width(f32::INFINITY));
                ui.horizontal(|ui| {
                    if ui.button("Read NDEF").clicked() {
                        self.ndef_read();
                    }
                    if ui.button("Write NDEF").clicked() {
                        self.ndef_write();
                    }
                });
                ui.weak("NDEF read/write targets NFC Forum Type 2 tags (NTAG/Ultralight), starting at page 4.");
                if !self.ndef_result.is_empty() {
                    ui.separator();
                    ui.monospace(&self.ndef_result);
                }
            }
        });
    }
}
