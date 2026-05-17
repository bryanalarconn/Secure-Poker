import secrets

# card settings
CARD_MIN = 1
CARD_MAX = 15
HAND_SIZE = 3

# round settings
NUM_ROUNDS = 3
ROUNDS_TO_WIN = 2

# result constants
P1_WIN = "player1"
P2_WIN = "player2"
TIE = "tie"
DRAW = "draw"

# secure random generator
_secure_rng = secrets.SystemRandom()

def deal_hand():
    # Pre: card range and hand size are valid
    # Post: returns a random hand with distinct cards
    return _secure_rng.sample(range(CARD_MIN, CARD_MAX + 1), HAND_SIZE)


def validate_choice(choice, hand):
    # Pre: hand is a list of cards
    # Post: returns True if the chosen card is in the hand
    return choice in hand


def compare_round(p1_choice, p2_choice):
    # Pre: both players have chosen a card
    # Post: returns the winner of the round, or tie
    if p1_choice > p2_choice:
        return P1_WIN
    if p2_choice > p1_choice:
        return P2_WIN
    return TIE


def determine_winner(round_results):
    # Pre: round_results contains the completed round outcomes
    # Post: returns the overall winner, or draw
    p1_wins = round_results.count(P1_WIN)
    p2_wins = round_results.count(P2_WIN)

    if p1_wins >= ROUNDS_TO_WIN:
        return P1_WIN
    if p2_wins >= ROUNDS_TO_WIN:
        return P2_WIN
    return DRAW
