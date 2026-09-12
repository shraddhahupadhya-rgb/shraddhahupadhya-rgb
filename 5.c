#include <stdio.h>
#include <string.h>
#include <ctype.h>

// ── STRUCTURE ─────────────────────────────────────────────
struct ScanResult {
    int  score;
    char risk_level[20];
    int  is_phishing;
};

// ── ARRAYS ────────────────────────────────────────────────
char keywords[6][15] = {"verify","secure","login","update","confirm","suspended"};
int  weights[6]      = {15, 15, 10, 10, 10, 20};
char bad_ext[5][8]   = {".xyz",".tk",".ml",".cf",".top"};
char otp_traps[4][15]= {"share otp","give otp","send otp","tell otp"};
char kyc_words[4][15]= {"kyc","aadhaar","pan card","blocked"};

// ── HELPER: lowercase ─────────────────────────────────────
void to_lower(char *s) {
    for (int i = 0; s[i]; i++)
        s[i] = tolower(s[i]);
}

// ── HELPER: assign risk from score ────────────────────────
void assign_risk(struct ScanResult *r) {
    if (r->score >= 50) {
        strcpy(r->risk_level, "CRITICAL");
        r->is_phishing = 1;
    } else if (r->score >= 25) {
        strcpy(r->risk_level, "MODERATE");
        r->is_phishing = 0;
    } else {
        strcpy(r->risk_level, "SAFE");
        r->is_phishing = 0;
    }
}

// ── FUNCTION 1: SCAN URL ──────────────────────────────────
void scan_url(char url[], struct ScanResult *r) {
    r->score = 0;
    char low[200];
    strcpy(low, url);
    to_lower(low);

    if (strncmp(low, "http://", 7) == 0)
        r->score += 20;

    for (int i = 0; i < 6; i++) {
        char *found = strstr(low, keywords[i]);
        if (found != NULL)
            r->score += weights[i];
    }

    for (int j = 0; j < 5; j++)
        if (strstr(low, bad_ext[j]) != NULL)
            r->score += 30;

    assign_risk(r);
}

// ── FUNCTION 2: SCAN EMAIL ────────────────────────────────
void scan_email(struct ScanResult *r) {
    char subject[100], sender[100], body[300];
    r->score = 0;

    printf("\nCyberGuard: What is the subject line?\n");
    printf("You: "); fgets(subject, 100, stdin);

    printf("CyberGuard: Who sent it?\n");
    printf("You: "); fgets(sender, 100, stdin);

    printf("CyberGuard: What does the body say?\n");
    printf("You: "); fgets(body, 300, stdin);

    to_lower(subject); to_lower(sender); to_lower(body);

    for (int i = 0; i < 6; i++) {
        if (strstr(subject, keywords[i]) != NULL) r->score += weights[i];
        if (strstr(body,    keywords[i]) != NULL) r->score += weights[i];
    }
    for (int j = 0; j < 5; j++)
        if (strstr(sender, bad_ext[j]) != NULL)
            r->score += 30;

    if (strstr(body, "http") != NULL)
        r->score += 25;

    assign_risk(r);
}

// ── FUNCTION 3: SCAN SMS ──────────────────────────────────
void scan_sms(struct ScanResult *r) {
    char msg[300];
    r->score = 0;

    printf("\nCyberGuard: Type out the SMS or WhatsApp message.\n");
    printf("You: "); fgets(msg, 300, stdin);
    to_lower(msg);

    for (int i = 0; i < 4; i++)
        if (strstr(msg, otp_traps[i]) != NULL) r->score += 35;

    for (int j = 0; j < 4; j++)
        if (strstr(msg, kyc_words[j]) != NULL) r->score += 20;

    for (int k = 0; k < 6; k++)
        if (strstr(msg, keywords[k]) != NULL) r->score += weights[k];

    if (strstr(msg, "http") != NULL)
        r->score += 25;

    assign_risk(r);
}

// ── MAIN ──────────────────────────────────────────────────
int main() {
    printf("==========================================\n");
    printf("   CYBERGUARD - Your Cyber Detective\n");
    printf("==========================================\n");

    struct ScanResult result;
    char choice[4], again[4];

    do {
        printf("\nCyberGuard: What do you want me to check?\n");
        printf("  [1] A suspicious URL\n");
        printf("  [2] A suspicious Email\n");
        printf("  [3] A suspicious SMS / WhatsApp\n");
        printf("  [0] Exit\n");
        printf("You: "); fgets(choice, 4, stdin);

        if (choice[0] == '1') {
            char url[200];
            printf("\nCyberGuard: Paste the URL.\n");
            printf("You: "); fgets(url, 200, stdin);
            url[strcspn(url, "\n")] = 0;
            scan_url(url, &result);

        } else if (choice[0] == '2') {
            scan_email(&result);

        } else if (choice[0] == '3') {
            scan_sms(&result);

        } else if (choice[0] == '0') {
            printf("\nCyberGuard: Stay safe. Goodbye.\n");
            return 0;
        }

        printf("\n------------------------------------------\n");
        printf("  Score : %d / 100\n", result.score);
        printf("  Risk  : %s\n", result.risk_level);
        if (result.is_phishing)
            printf("  CyberGuard: Phishing detected! Do NOT respond.\n");
        else
            printf("  CyberGuard: Looks safe. But stay alert.\n");
        printf("------------------------------------------\n");

        printf("\nCyberGuard: Want to check something else? (y/n)\n");
        printf("You: "); fgets(again, 4, stdin);

    } while (again[0] == 'y' || again[0] == 'Y');

    printf("\nCyberGuard: Stay safe. Goodbye.\n");
    return 0;
}