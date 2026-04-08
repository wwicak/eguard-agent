#![cfg(target_os = "macos")]

use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use cocoa::appkit::{
    NSApplication, NSApplicationActivationPolicyRegular, NSBackingStoreBuffered, NSMenu,
    NSMenuItem, NSStatusBar, NSVariableStatusItemLength, NSWindow, NSWindowStyleMask,
};
use cocoa::base::{id, nil, NO};
use cocoa::foundation::{NSAutoreleasePool, NSPoint, NSRect, NSSize, NSString};
use objc::declare::ClassDecl;
use objc::runtime::{Object, Sel};
use objc::{class, msg_send, sel, sel_impl};

use crate::app;

pub fn run_menu_bar() -> Result<()> {
    unsafe {
        let _pool = NSAutoreleasePool::new(nil);
        let app_instance = NSApplication::sharedApplication(nil);
        app_instance.setActivationPolicy_(NSApplicationActivationPolicyRegular);

        let delegate = create_delegate()?;
        retain_delegate(delegate);
        let _: () = msg_send![app_instance, setDelegate: delegate];
        let _: () = msg_send![app_instance, run];
    }
    Ok(())
}

fn retain_delegate(delegate: id) {
    static DELEGATE_PTR: AtomicUsize = AtomicUsize::new(0);
    DELEGATE_PTR.store(delegate as usize, Ordering::SeqCst);
}

fn retain_status_item(status_item: id) {
    static STATUS_ITEM_PTR: AtomicUsize = AtomicUsize::new(0);
    STATUS_ITEM_PTR.store(status_item as usize, Ordering::SeqCst);
}

fn retain_window(window: id) {
    static WINDOW_PTR: AtomicUsize = AtomicUsize::new(0);
    WINDOW_PTR.store(window as usize, Ordering::SeqCst);
}

unsafe fn create_delegate() -> Result<id> {
    let superclass = class!(NSObject);
    let mut decl = ClassDecl::new("EguardTrayAppDelegate", superclass)
        .ok_or_else(|| anyhow::anyhow!("delegate_class_decl_failed"))?;
    decl.add_ivar::<id>("statusItem");
    decl.add_ivar::<id>("menu");
    decl.add_ivar::<id>("window");
    decl.add_method(
        sel!(applicationDidFinishLaunching:),
        did_finish_launching as extern "C" fn(&mut Object, Sel, id),
    );
    decl.add_method(
        sel!(refreshMenu:),
        refresh_menu as extern "C" fn(&Object, Sel, id),
    );
    decl.add_method(
        sel!(openBookmark:),
        open_bookmark as extern "C" fn(&Object, Sel, id),
    );
    decl.add_method(
        sel!(disconnectSession:),
        disconnect_session as extern "C" fn(&Object, Sel, id),
    );
    decl.add_method(
        sel!(disconnectAll:),
        disconnect_all as extern "C" fn(&Object, Sel, id),
    );
    decl.add_method(
        sel!(disableTransport:),
        disable_transport as extern "C" fn(&Object, Sel, id),
    );
    decl.add_method(
        sel!(enableTransport:),
        enable_transport as extern "C" fn(&Object, Sel, id),
    );
    decl.add_method(sel!(noop:), noop as extern "C" fn(&Object, Sel, id));
    decl.add_method(sel!(quitApp:), quit_app as extern "C" fn(&Object, Sel, id));
    let class = decl.register();
    let delegate: id = msg_send![class, new];
    Ok(delegate)
}

extern "C" fn did_finish_launching(this: &mut Object, _: Sel, _: id) {
    unsafe {
        let status_bar = NSStatusBar::systemStatusBar(nil);
        let status_item = status_bar.statusItemWithLength_(NSVariableStatusItemLength);
        let button: id = msg_send![status_item, button];
        let title = NSString::alloc(nil).init_str("eGuard");
        let _: () = msg_send![button, setTitle: title];

        let menu = NSMenu::new(nil);
        let frame = NSRect::new(NSPoint::new(0., 0.), NSSize::new(440., 160.));
        let style = NSWindowStyleMask::NSTitledWindowMask
            | NSWindowStyleMask::NSClosableWindowMask
            | NSWindowStyleMask::NSMiniaturizableWindowMask;
        let window = NSWindow::alloc(nil).initWithContentRect_styleMask_backing_defer_(
            frame,
            style,
            NSBackingStoreBuffered,
            NO,
        );
        let _: () = msg_send![window, center];
        let _: () =
            msg_send![window, setTitle: NSString::alloc(nil).init_str("eGuard Tray Started")];
        let _: () = msg_send![window, makeKeyAndOrderFront: nil];
        this.set_ivar("statusItem", status_item);
        this.set_ivar("menu", menu);
        this.set_ivar("window", window);
        retain_status_item(status_item);
        retain_window(window);

        rebuild_menu(this, menu);
        let _: () = msg_send![status_item, setMenu: menu];

        let this_ptr = this as *const Object as usize;
        thread::spawn(move || loop {
            unsafe {
                let obj = &*(this_ptr as *const Object);
                let _: () = msg_send![obj, performSelectorOnMainThread: sel!(refreshMenu:) withObject: nil waitUntilDone: NO];
            }
            thread::sleep(Duration::from_secs(5));
        });
    }
}

extern "C" fn refresh_menu(this: &Object, _: Sel, _: id) {
    unsafe {
        let menu: id = *this.get_ivar("menu");
        rebuild_menu(this, menu);
    }
}

unsafe fn rebuild_menu(_this: &Object, menu: id) {
    let _: () = msg_send![menu, removeAllItems];

    let bookmarks = app::bookmarks_state().ok();
    let sessions = app::sessions_state().ok();

    add_title(menu, "eGuard ZTNA");
    add_separator(menu);

    add_title(menu, "Bookmarks");
    if let Some(bookmarks) = bookmarks {
        if bookmarks.bookmarks.is_empty() {
            add_disabled(menu, "No bookmarks available");
        } else {
            for bookmark in bookmarks.bookmarks.iter().take(10) {
                let item = add_action(menu, &bookmark.name, sel!(openBookmark:));
                let represented = NSString::alloc(nil).init_str(&bookmark.app_id);
                let _: () = msg_send![item, setRepresentedObject: represented];
            }
        }
    } else {
        add_disabled(menu, "Bookmark cache not found");
    }

    add_separator(menu);
    add_title(menu, "Sessions");
    if let Some(sessions) = sessions {
        if sessions.sessions.is_empty() {
            add_disabled(menu, "No active sessions");
        } else {
            for session in sessions.sessions.iter().take(10) {
                let label = format!("Disconnect {}", session.name);
                let item = add_action(menu, &label, sel!(disconnectSession:));
                let represented = NSString::alloc(nil).init_str(&session.session_id);
                let _: () = msg_send![item, setRepresentedObject: represented];
            }
        }
        add_separator(menu);
        add_action(menu, "Disconnect All", sel!(disconnectAll:));
        if sessions.transport_disabled {
            add_action(menu, "Enable Transport", sel!(enableTransport:));
        } else {
            add_action(menu, "Disable Transport", sel!(disableTransport:));
        }
    } else {
        add_disabled(menu, "Session state unavailable");
    }

    add_separator(menu);
    add_action(menu, "Refresh", sel!(refreshMenu:));
    add_action(menu, "Quit", sel!(quitApp:));
}

extern "C" fn open_bookmark(_: &Object, _: Sel, sender: id) {
    unsafe {
        if let Some(app_id) = represented_string(sender) {
            let _ = app::open_bookmark(&app_id);
        }
    }
}

extern "C" fn disconnect_session(_: &Object, _: Sel, sender: id) {
    unsafe {
        if let Some(session_id) = represented_string(sender) {
            let _ = app::disconnect_session(&session_id);
        }
    }
}

extern "C" fn disconnect_all(_: &Object, _: Sel, _: id) {
    let _ = app::disconnect_all_sessions();
}

extern "C" fn disable_transport(_: &Object, _: Sel, _: id) {
    let _ = app::disable_transport();
}

extern "C" fn enable_transport(_: &Object, _: Sel, _: id) {
    let _ = app::enable_transport();
}

extern "C" fn quit_app(_: &Object, _: Sel, _: id) {
    unsafe {
        let app = NSApplication::sharedApplication(nil);
        let _: () = msg_send![app, terminate: nil];
    }
}

extern "C" fn noop(_: &Object, _: Sel, _: id) {}

unsafe fn represented_string(sender: id) -> Option<String> {
    let represented: id = msg_send![sender, representedObject];
    if represented == nil {
        return None;
    }
    let c_str: *const c_char = msg_send![represented, UTF8String];
    if c_str.is_null() {
        return None;
    }
    Some(CStr::from_ptr(c_str).to_string_lossy().into_owned())
}

unsafe fn add_title(menu: id, title: &str) {
    let item = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
        NSString::alloc(nil).init_str(title),
        sel!(noop:),
        NSString::alloc(nil).init_str(""),
    );
    let _: () = msg_send![item, setEnabled: NO];
    let _: () = msg_send![menu, addItem: item];
}

unsafe fn add_disabled(menu: id, title: &str) {
    add_title(menu, title);
}

unsafe fn add_action(menu: id, title: &str, action: Sel) -> id {
    let item = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
        NSString::alloc(nil).init_str(title),
        action,
        NSString::alloc(nil).init_str(""),
    );
    let app = NSApplication::sharedApplication(nil);
    let _: () = msg_send![item, setTarget: app];
    let delegate: id = msg_send![app, delegate];
    let _: () = msg_send![item, setTarget: delegate];
    let _: () = msg_send![menu, addItem: item];
    item
}

unsafe fn add_separator(menu: id) {
    let item = NSMenuItem::separatorItem(nil);
    let _: () = msg_send![menu, addItem: item];
}
