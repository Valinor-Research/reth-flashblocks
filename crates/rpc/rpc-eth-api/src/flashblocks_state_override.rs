use alloy_evm::overrides::StateOverrideError;
use alloy_primitives::{
    keccak256,
    map::{AddressHashMap, B256HashMap, HashMap},
    Address, Bytes, B256, U256,
};
use revm::{
    state::{Account, AccountStatus, Bytecode, EvmStorageSlot},
    Database, DatabaseCommit,
};
use serde::{Deserialize, Serialize};

/// A set of flashblocks account overrides.
pub(crate) type FlashblocksStateOverride = AddressHashMap<FlashblocksAccountOverride>;

/// A copy of [`AccountOverride`] without the serde skip_serializing_if attributes that break
/// non-descriptive encodings such as postcard.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct FlashblocksAccountOverride {
    /// Fake balance to set for the account before executing the call.
    pub balance: Option<U256>,
    /// Fake nonce to set for the account before executing the call.
    pub nonce: Option<u64>,
    /// Fake EVM bytecode to inject into the account before executing the call.
    pub code: Option<Bytes>,
    /// Fake key-value mapping to override all slots in the account storage before executing the
    /// call.
    pub state: Option<B256HashMap<B256>>,
    /// Fake key-value mapping to override individual slots in the account storage before executing
    /// the call.
    pub state_diff: Option<B256HashMap<B256>>,
    /// Moves addresses precompile into the specified address. This move is done before the 'code'
    /// override is set. When the specified address is not a precompile, the behaviour is undefined
    /// and different clients might behave differently.
    pub move_precompile_to: Option<Address>,
}

/// Applies the given state overrides (a set of [`FlashblocksStateOverride`]) to the database.
pub(crate) fn apply_flashblocks_state_overrides<DB>(
    overrides: FlashblocksStateOverride,
    db: &mut DB,
) -> Result<(), StateOverrideError<DB::Error>>
where
    DB: Database + DatabaseCommit,
{
    for (account, account_overrides) in overrides {
        apply_flashblocks_account_override(account, account_overrides, db)?;
    }
    Ok(())
}

/// Applies a single [`FlashblocksAccountOverride`] to the database.
fn apply_flashblocks_account_override<DB>(
    account: Address,
    account_override: FlashblocksAccountOverride,
    db: &mut DB,
) -> Result<(), StateOverrideError<DB::Error>>
where
    DB: Database + DatabaseCommit,
{
    let mut info = db.basic(account).map_err(StateOverrideError::Database)?.unwrap_or_default();

    if let Some(nonce) = account_override.nonce {
        info.nonce = nonce;
    }
    if let Some(code) = account_override.code {
        // we need to set both the bytecode and the codehash
        info.code_hash = keccak256(&code);
        info.code = Some(Bytecode::new_raw_checked(code)?);
    }
    if let Some(balance) = account_override.balance {
        info.balance = balance;
    }

    // Create a new account marked as touched
    let mut acc = revm::state::Account {
        info,
        status: AccountStatus::Touched,
        storage: Default::default(),
        transaction_id: 0,
    };

    let storage_diff = match (account_override.state, account_override.state_diff) {
        (Some(_), Some(_)) => return Err(StateOverrideError::BothStateAndStateDiff(account)),
        (None, None) => None,
        // If we need to override the entire state, we firstly mark account as destroyed to clear
        // its storage, and then we mark it is "NewlyCreated" to make sure that old storage won't be
        // used.
        (Some(state), None) => {
            // Destroy the account to ensure that its storage is cleared
            db.commit(HashMap::from_iter([(
                account,
                Account {
                    status: AccountStatus::SelfDestructed | AccountStatus::Touched,
                    ..Default::default()
                },
            )]));
            // Mark the account as created to ensure that old storage is not read
            acc.mark_created();
            Some(state)
        }
        (None, Some(state)) => Some(state),
    };

    if let Some(state) = storage_diff {
        for (slot, value) in state {
            acc.storage.insert(
                slot.into(),
                EvmStorageSlot {
                    // we use inverted value here to ensure that storage is treated as changed
                    original_value: (!value).into(),
                    present_value: value.into(),
                    is_cold: false,
                    transaction_id: 0,
                },
            );
        }
    }

    db.commit(HashMap::from_iter([(account, acc)]));

    Ok(())
}
