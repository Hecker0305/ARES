package scheduler

type Schedule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Target   string `json:"target"`
	CronExpr string `json:"cron_expr"`
	Enabled  bool   `json:"enabled"`
}

type Scheduler struct {
	runScanFn func(string)
	schedules map[string]*Schedule
}

func New(path string, defaultFn func(string)) *Scheduler {
	return &Scheduler{runScanFn: defaultFn, schedules: make(map[string]*Schedule)}
}

func (s *Scheduler) AddSchedule(sched *Schedule) {
	s.schedules[sched.ID] = sched
}

func (s *Scheduler) SetRunScanFunc(fn func(target string)) {
	s.runScanFn = fn
}

func (s *Scheduler) Start() {}

func (s *Scheduler) Stop() {}
