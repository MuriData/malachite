//! Consensus pairs a proposal without a proof-of-lock round only with a value reported for the
//! proposal's own round.
//!
//! Such a proposal proposes a value built in its round (L14–L19). If it paired with a copy of the
//! same value reported for an earlier round, a later proposer could propose an old value as new
//! and validators would prevote it on the earlier copy's verdict, skipping the checks an
//! application applies only to a value built in the current round.

use std::vec::Vec;

use arc_malachitebft_core_consensus::{
    process, Effect, Error, Input, Params, ProposedValue, Resumable, Resume, SignedConsensusMsg,
    State, ValuePayload,
};
use malachitebft_core_types::{
    NilOrVal, Round, SignedProposal, SignedVote, Validity, ValueOrigin, VoteType,
};
use malachitebft_metrics::Metrics;
use malachitebft_test::utils::validators::make_validators;
use malachitebft_test::{
    Address, Height, Proposal, Signature, TestContext, Validator, ValidatorSet, Value, Vote,
};

const X: u64 = 9999;

#[derive(Default)]
struct Captured {
    wal: Vec<Input<TestContext>>,
    published_votes: Vec<SignedVote<TestContext>>,
}

fn handle_effect(
    effect: Effect<TestContext>,
    cap: &mut Captured,
) -> Result<Resume<TestContext>, ()> {
    use Effect::*;
    Ok(match effect {
        VerifySignature(_, _, r) => r.resume_with(true),
        VerifyPolkaCertificate(_, _, _, r) => r.resume_with(Ok(())),
        VerifyRoundCertificate(_, _, _, r) => r.resume_with(Ok(())),
        VerifyCommitCertificate(_, _, _, r) => r.resume_with(Ok(())),
        SignVote(vote, r) => r.resume_with(SignedVote::new(vote, Signature::test())),
        SignProposal(proposal, r) => {
            r.resume_with(SignedProposal::new(proposal, Signature::test()))
        }
        ExtendVote(_, _, _, _, r) => r.resume_with(None),
        VerifyVoteExtension(_, _, _, _, _, _, r) => r.resume_with(Ok(())),
        WalAppend(_, input, r) => {
            cap.wal.push(input);
            r.resume_with(())
        }
        PublishConsensusMsg(msg, r) => {
            if let SignedConsensusMsg::Vote(vote) = msg {
                cap.published_votes.push(vote);
            }
            r.resume_with(())
        }
        _ => Resume::Continue,
    })
}

fn validators() -> Vec<Validator> {
    make_validators([1, 1, 1, 1])
        .into_iter()
        .map(|(v, _)| v)
        .collect()
}

fn proposer(validators: &[Validator], round: u32) -> Address {
    TestContext::new()
        .select_proposer(
            &ValidatorSet::new(validators.to_vec()),
            Height::new(1),
            Round::new(round),
        )
        .address
}

/// The validators that propose neither in round 0 nor in round 2.
fn bystanders(validators: &[Validator]) -> Vec<Address> {
    let proposers = [proposer(validators, 0), proposer(validators, 2)];
    validators
        .iter()
        .map(|v| v.address)
        .filter(|addr| !proposers.contains(addr))
        .collect()
}

fn make_state(validators: &[Validator], my_addr: Address) -> State<TestContext> {
    State::new(
        TestContext::new(),
        Height::new(1),
        ValidatorSet::new(validators.to_vec()),
        Params {
            address: my_addr,
            threshold_params: Default::default(),
            value_payload: ValuePayload::ProposalAndParts,
            enabled: true,
        },
        1000,
        1000,
    )
}

fn start_height(validators: &[Validator], is_restart: bool) -> Input<TestContext> {
    Input::StartHeight(
        Height::new(1),
        ValidatorSet::new(validators.to_vec()),
        is_restart,
        None,
        Default::default(),
    )
}

/// A round 2 nil prevote from `addr`. Votes from f+1 validators move a node in round 0 to round 2
/// (L55).
fn round_2_prevote(addr: Address) -> Input<TestContext> {
    Input::Vote(SignedVote::new(
        Vote::new_prevote(Height::new(1), Round::new(2), NilOrVal::Nil, addr),
        Signature::test(),
    ))
}

fn nil_proposal(proposer: Address, round: u32) -> Input<TestContext> {
    Input::Proposal(SignedProposal::new(
        Proposal::new(
            Height::new(1),
            Round::new(round),
            Value::new(X),
            Round::Nil,
            proposer,
        ),
        Signature::test(),
    ))
}

/// The application's report of `X`, built in `round`.
fn value(proposer: Address, round: u32, validity: Validity) -> Input<TestContext> {
    Input::ProposedValue(
        ProposedValue {
            height: Height::new(1),
            round: Round::new(round),
            valid_round: Round::Nil,
            proposer,
            value: Value::new(X),
            validity,
        },
        ValueOrigin::Consensus,
    )
}

/// Drive `inputs` into `state`. Step tracking needs `metrics` shared across calls on one state.
fn drive(
    state: &mut State<TestContext>,
    metrics: &Metrics,
    inputs: Vec<Input<TestContext>>,
) -> Captured {
    let mut cap = Captured::default();
    for input in inputs {
        let result: Result<(), Error<TestContext>> = process!(
            input: input,
            state: state,
            metrics: metrics,
            with: e => handle_effect(e, &mut cap)
        );
        result.expect("consensus input should process successfully");
    }
    cap
}

fn prevoted_x_in_round_2(cap: &Captured) -> bool {
    cap.published_votes.iter().any(|vote| {
        vote.message.typ == VoteType::Prevote
            && vote.message.round == Round::new(2)
            && vote.message.value == NilOrVal::Val(Value::new(X).id())
    })
}

/// The node in round 2 has the round 0 copy of `X` and a round 2 proposal of `X` without a
/// proof-of-lock round.
fn relabel_inputs(validators: &[Validator]) -> Vec<Input<TestContext>> {
    let others = bystanders(validators);
    vec![
        start_height(validators, false),
        round_2_prevote(others[1]),
        round_2_prevote(proposer(validators, 0)),
        value(proposer(validators, 0), 0, Validity::Valid),
        nil_proposal(proposer(validators, 2), 2),
    ]
}

#[test]
fn nil_proposal_is_not_prevoted_on_an_earlier_round_copy() {
    let validators = validators();
    let mut state = make_state(&validators, bystanders(&validators)[0]);
    let metrics = Metrics::new();

    let cap = drive(&mut state, &metrics, relabel_inputs(&validators));
    assert_eq!(state.round(), Round::new(2));
    assert!(!prevoted_x_in_round_2(&cap));

    // The copy reported for round 2 completes the proposal.
    let cap = drive(
        &mut state,
        &metrics,
        vec![value(proposer(&validators, 2), 2, Validity::Valid)],
    );
    assert!(prevoted_x_in_round_2(&cap));
}

#[test]
fn nil_proposal_is_judged_by_its_round_copy() {
    let validators = validators();
    let mut state = make_state(&validators, bystanders(&validators)[0]);

    let mut inputs = relabel_inputs(&validators);
    inputs.push(value(proposer(&validators, 2), 2, Validity::Invalid));
    let cap = drive(&mut state, &Metrics::new(), inputs);

    assert!(!prevoted_x_in_round_2(&cap));
    let full = state
        .full_proposal_at_round_and_value(&Height::new(1), Round::new(2), &Value::new(X))
        .expect("the round 2 copy completes the proposal");
    assert_eq!(full.validity, Validity::Invalid);
}

#[test]
fn replayed_relabel_is_not_prevoted() {
    let validators = validators();
    let me = bystanders(&validators)[0];
    let mut state = make_state(&validators, me);
    let captured = drive(&mut state, &Metrics::new(), relabel_inputs(&validators));

    let mut replay = vec![start_height(&validators, true)];
    replay.extend(captured.wal.iter().cloned());
    let mut replay_state = make_state(&validators, me);
    let cap = drive(&mut replay_state, &Metrics::new(), replay);

    assert_eq!(replay_state.round(), Round::new(2));
    assert!(!prevoted_x_in_round_2(&cap));
    assert!(replay_state
        .full_proposal_at_round_and_value(&Height::new(1), Round::new(2), &Value::new(X))
        .is_none());
}
