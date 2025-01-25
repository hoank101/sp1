//! Data that may be collected during execution and used to estimate trace area.

use std::ops::AddAssign;

use enum_map::EnumMap;
use hashbrown::HashMap;
use sp1_stark::SP1CoreOpts;

use crate::RiscvAirId;

const BYTE_NUM_ROWS: u64 = 1 << 16;

/// Data accumulated during execution to estimate the core trace area used to prove the execution.
#[derive(Clone, Debug, Default)]
pub struct TraceAreaEstimator {
    /// Core shards, represented by the number of events per AIR.
    pub core_shards: Vec<EnumMap<RiscvAirId, u64>>,
    /// Deferred events, which are used to calculate trace area after execution has finished.
    pub deferred_events: EnumMap<RiscvAirId, u64>,
}

impl TraceAreaEstimator {
    /// An estimate of the total trace area required for the core proving stage.
    /// This provides a prover gas metric.
    #[must_use]
    #[deprecated]
    pub fn total_trace_area(
        &self,
        program_len: usize,
        costs: &HashMap<RiscvAirId, u64>,
        opts: &SP1CoreOpts,
    ) -> u64 {
        let core_area = 0u64;

        let deferred_area = self
            .deferred_events
            .iter()
            .map(|(id, &count)| {
                let threshold = match id {
                    RiscvAirId::ShaExtend => opts.split_opts.sha_extend,
                    RiscvAirId::ShaCompress => opts.split_opts.sha_compress,
                    RiscvAirId::KeccakPermute => opts.split_opts.keccak,
                    RiscvAirId::MemoryGlobalInit | RiscvAirId::MemoryGlobalFinalize => {
                        opts.split_opts.memory
                    }
                    _ => opts.split_opts.deferred,
                };
                let rows_per_event = id.rows_per_event() as u64;
                let threshold = threshold as u64;
                let rows = count * rows_per_event;
                let num_full_airs = rows / threshold;
                let num_remainder_air_rows = rows % threshold;
                let num_padded_rows = num_full_airs * threshold.next_power_of_two()
                    + num_remainder_air_rows.next_power_of_two();
                // The costs already seem to include the `rows_per_event` factor.
                let cost_per_row = costs[&id] / rows_per_event;
                cost_per_row * num_padded_rows
            })
            .sum::<u64>();

        let byte_area = BYTE_NUM_ROWS * costs[&RiscvAirId::Byte];

        // // Compute the program chip contribution.
        let program_area = program_len as u64 * costs[&RiscvAirId::Program];

        core_area + deferred_area + byte_area + program_area
    }
}

impl AddAssign for TraceAreaEstimator {
    fn add_assign(&mut self, rhs: Self) {
        let TraceAreaEstimator { core_shards, deferred_events } = self;
        core_shards.extend(rhs.core_shards);
        deferred_events
            .as_mut_array()
            .iter_mut()
            .zip(rhs.deferred_events.as_array())
            .for_each(|(l, r)| *l += r);
    }
}
