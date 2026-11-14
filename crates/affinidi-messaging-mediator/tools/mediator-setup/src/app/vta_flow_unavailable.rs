//! The VTA step in a build without the `vta` feature.
//!
//! vta-sdk is out of the dependency graph for this release, so the online
//! and sealed-handoff sub-flows (`vta_flow.rs`) are not built. The VTA step
//! offers only "No VTA" (see `VTA_INTENT_CHOICES`); these are the entry points
//! the rest of the wizard calls, with the sub-flows never active. Step 3 of
//! the release order (vta-sdk back in the graph) deletes this file.

use crate::vta::{VTA_UNAVAILABLE, VtaIntent};

use super::{VtaStepPhase, WizardApp};

impl WizardApp {
    /// Refuse a VTA intent: stay on the VTA step's first question with the
    /// reason on screen. Unreachable from the picker, which lists no VTA
    /// intent in this build.
    fn refuse_vta(&mut self) {
        self.vta_intent_choice = None;
        self.vta_step_phase = VtaStepPhase::SelectIntent;
        self.config.use_vta = false;
        self.config.vta_mode = None;
        self.selection_index = 0;
        self.vta_stub_notice = Some(VTA_UNAVAILABLE.into());
    }

    pub(super) fn enter_sealed_handoff_subflow(&mut self, _intent: VtaIntent) {
        self.refuse_vta();
    }

    pub(super) fn enter_vta_subflow(&mut self, _intent: VtaIntent) {
        self.refuse_vta();
    }

    /// Never true: the sealed-handoff sub-flow does not exist in this build.
    pub fn in_sealed_handoff_subflow(&self) -> bool {
        false
    }

    /// Never true: the online VTA sub-flow does not exist in this build.
    pub fn in_vta_subflow(&self) -> bool {
        false
    }

    /// Only called while [`Self::in_sealed_handoff_subflow`]; nothing to do.
    pub(super) fn sealed_handoff_select(&mut self) {}

    /// Only called while [`Self::in_sealed_handoff_subflow`]; never consumes
    /// the input.
    pub(super) fn sealed_handoff_confirm_text(&mut self) -> bool {
        false
    }

    /// Only called while [`Self::in_sealed_handoff_subflow`]; nothing to do.
    pub(super) fn sealed_handoff_back(&mut self) {}

    /// Only called while [`Self::in_vta_subflow`]; nothing to do.
    pub(super) fn vta_subflow_select(&mut self) {}

    /// Only called while [`Self::in_vta_subflow`]; nothing to do.
    pub(super) fn vta_subflow_confirm_text(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Only called while [`Self::in_vta_subflow`]; nothing to do.
    pub(super) fn vta_subflow_back(&mut self) {}

    /// No provision flight can run in this build; nothing to drain.
    pub fn drain_vta_events(&mut self) {}
}
