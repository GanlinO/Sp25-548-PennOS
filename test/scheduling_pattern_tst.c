#include <stdio.h>
#include <stdlib.h>

void ratio_method(int trial_total, int cap) {

  // scheduling counter for each queue
  int run[3] = {0};
  // priority ratio
  double ratio[2] = {1.5, 1.5};
  // counter of scheduling cycles
  int overall = 0;
  // pick of next queue
  int next = -1;
  // cumulative counter for each queue
  int real_cnt[3] = {0};

  fprintf(stderr, "cycle\tnext\trun[]\t\treal counts\treal ratio\n");

  while (overall++ < trial_total) {
    if (run[0] <= (run[1]) * ratio[0]) {
      next = 0;
    } else if (run[1] <= (run[2]) * ratio[1]) {
      next = 1;
    } else {
      next = 2;

      if (run[0] > cap) {
        int oldrun[2];
        oldrun[0] = run[0];
        oldrun[1] = run[1];
        
        run[0] -= run[2] * ratio[1] * ratio[0];
        run[1] -= run[2] * ratio[1];
        fprintf(stderr, "-- subtract: %3d %3d %3d--\n", oldrun[0] - run[0], oldrun[1] - run[1], run[2]);
        run[2] = 0;
      }
    }

    ++run[next];
    ++real_cnt[next];

    fprintf(stderr, "[%d]\t%d\t%3d %3d %3d\t%3d %3d %3d\t%0.2f %0.2f\n", 
      overall, next, run[0], run[1], run[2],
      real_cnt[0], real_cnt[1], real_cnt[2],
      (double) real_cnt[0] / real_cnt[1], (double) real_cnt[1] / real_cnt[2]
    );
  }
}

void ticket_method(int trial_total) {
  int weight[3] = {9, 6, 4};
  int total_weight = weight[0] + weight[1] + weight[2];
  int ticket[3] = {0, 0, 0};
  int overall = 0;
  int next = -1;
  // cumulative counter for each queue
  int real_cnt[3] = {0};

  fprintf(stderr, "cycle\tnext\tticket[]\treal counts\treal ratio\n");
  fprintf(stderr, "[%d]\t%d\t%3d %3d %3d\t%3d %3d %3d\t%0.2f %0.2f\n",
    overall, next, ticket[0], ticket[1], ticket[2],
    real_cnt[0], real_cnt[1], real_cnt[2],
    (double) real_cnt[0] / real_cnt[1], (double) real_cnt[1] / real_cnt[2]
  );

  while (overall++ < trial_total) {
    for (int i = 0; i < 3; ++i) {
      ticket[i] += weight[i];
    }

    next = 0;
    for (int i = 1; i < 3; ++i) {
      if (ticket[i] > ticket[next]) {
        next = i;
      }
    }

    ++real_cnt[next];
    ticket[next] -= total_weight;

    fprintf(stderr, "[%d]\t%d\t%3d %3d %3d\t%3d %3d %3d\t%0.2f %0.2f\n", 
      overall, next, ticket[0], ticket[1], ticket[2],
      real_cnt[0], real_cnt[1], real_cnt[2],
      (double) real_cnt[0] / real_cnt[1], (double) real_cnt[1] / real_cnt[2]
    );
  }
}

void ticket_method2(int trial_total) {
  int weight[3] = {9, 6, 4};
  int total_weight = weight[0] + weight[1] + weight[2];
  int ticket[3] = {0, 0, 0};
  int max_ticket;
  int overall = 0;
  int next = -1;
  // cumulative counter for each queue
  int real_cnt[3] = {0};

  fprintf(stderr, "cycle\tnext\tticket[]\treal counts\treal ratio\n");
  fprintf(stderr, "[%d]\t%d\t%3d %3d %3d\t%3d %3d %3d\t%0.2f %0.2f\n",
    overall, next, ticket[0], ticket[1], ticket[2],
    real_cnt[0], real_cnt[1], real_cnt[2],
    (double) real_cnt[0] / real_cnt[1], (double) real_cnt[1] / real_cnt[2]
  );

  while (overall++ < trial_total) {
    next = 0;
    ticket[0] += weight[0];
    max_ticket = weight[0];

    for (int i = 1; i < 3; ++i) {
      ticket[i] += weight[i];

      if (ticket[i] > max_ticket) {
        max_ticket = ticket[i];
        next = i;
      }
    }

    ++real_cnt[next];
    ticket[next] -= total_weight;

    fprintf(stderr, "[%d]\t%d\t%3d %3d %3d\t%3d %3d %3d\t%0.2f %0.2f\n", 
      overall, next, ticket[0], ticket[1], ticket[2],
      real_cnt[0], real_cnt[1], real_cnt[2],
      (double) real_cnt[0] / real_cnt[1], (double) real_cnt[1] / real_cnt[2]
    );
  }
}

int main(int argc, char* argv[]) {

  int trial_total, cap;
  if (argc < 3) {
    trial_total = 100;
    cap = 9;
  } else {
    trial_total = atoi(argv[1]);
    if (trial_total <= 0) {
      trial_total = 100;
    }

    cap = atoi(argv[2]);
    if (cap <= 0) {
      cap = 9;
    }
  }

  ticket_method2(trial_total);

}