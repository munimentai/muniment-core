use std::path::PathBuf;

use muniment_core::chat_view::{
    chat_attachments, chat_pending_permission, chat_tool_activity, projection_phase, SelectedFile,
};
use muniment_core::journal::reducer::{
    AttentionReason, PermissionGate, PermissionRequest, ProjectedAttachment, RunStatus,
    ToolActivity, ToolActivityStatus,
};
use serde_json::json;

#[test]
fn selected_file_uses_the_webview_contract() {
    let file: SelectedFile = serde_json::from_value(json!({"path": "/work/note.txt"})).unwrap();
    assert_eq!(file.path, PathBuf::from("/work/note.txt"));
    assert!(serde_json::from_value::<SelectedFile>(
        json!({"path": "/work/note.txt", "unexpected": true})
    )
    .is_err());
}

#[test]
fn attachments_use_the_webview_contract() {
    let attachments = chat_attachments(&[
        ProjectedAttachment {
            display_name: "note.txt".into(),
            byte_length: 42,
            media_type: Some("text/plain".into()),
        },
        ProjectedAttachment {
            display_name: "unknown".into(),
            byte_length: 0,
            media_type: None,
        },
    ]);

    assert_eq!(
        serde_json::to_value(attachments).unwrap(),
        json!([
            {"displayName": "note.txt", "byteLength": 42, "mediaType": "text/plain"},
            {"displayName": "unknown", "byteLength": 0}
        ])
    );
    assert!(chat_attachments(&[]).is_empty());
}

#[test]
fn pending_permission_uses_the_webview_contract() {
    let permission = chat_pending_permission(Some(PermissionGate {
        gate_id: "gate-1".into(),
        request: PermissionRequest::Confirm {
            title: "Allow?".into(),
            message: "Run the tool?".into(),
            timeout: None,
        },
    }));

    assert_eq!(
        serde_json::to_value(permission).unwrap(),
        json!({
            "gateId": "gate-1",
            "kind": "confirm",
            "title": "Allow?",
            "message": "Run the tool?"
        })
    );
    assert!(chat_pending_permission(None).is_none());

    assert!(chat_pending_permission(Some(PermissionGate {
        gate_id: "code-gate".into(),
        request: PermissionRequest::CodeDiff {
            effect_id: "effect-1".into(),
            code_diff_id: "diff-1".into(),
            diff_sha256: "aa".into(),
            write_plan_sha256: "bb".into(),
        },
    }))
    .is_none());
}

#[test]
fn tool_activity_uses_the_webview_contract() {
    let activity = chat_tool_activity(&[
        ToolActivity {
            effect_id: "effect-1".into(),
            display_name: Some("Search".into()),
            status: ToolActivityStatus::Running,
        },
        ToolActivity {
            effect_id: "effect-2".into(),
            display_name: None,
            status: ToolActivityStatus::Completed,
        },
        ToolActivity {
            effect_id: "effect-3".into(),
            display_name: None,
            status: ToolActivityStatus::Failed,
        },
    ]);

    assert_eq!(
        serde_json::to_value(activity).unwrap(),
        json!([
            {"effectId": "effect-1", "displayName": "Search", "status": "running"},
            {"effectId": "effect-2", "displayName": null, "status": "completed"},
            {"effectId": "effect-3", "displayName": null, "status": "failed"}
        ])
    );
    assert!(chat_tool_activity(&[]).is_empty());
}

#[test]
fn projection_phase_maps_every_status() {
    let pending = PermissionGate {
        gate_id: "gate-1".into(),
        request: PermissionRequest::Confirm {
            title: "Allow?".into(),
            message: "Run the tool?".into(),
            timeout: None,
        },
    };
    let cases = [
        (None, "thinking"),
        (Some(RunStatus::Active), "thinking"),
        (Some(RunStatus::Streaming), "streaming"),
        (Some(RunStatus::Completed), "complete"),
        (Some(RunStatus::Cancelled), "cancelled"),
        (Some(RunStatus::Failed { reason: None }), "failed"),
        (
            Some(RunStatus::NeedsAttention(AttentionReason::Recorded {
                reason: "unknown".into(),
            })),
            "interrupted",
        ),
        (
            Some(RunStatus::PendingPermission(pending)),
            "pending-permission",
        ),
    ];

    for (status, expected) in cases {
        assert_eq!(projection_phase(&status), expected);
    }
}
